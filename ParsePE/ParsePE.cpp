#include <iostream>
#include "PEParser.h"


namespace {
	template <typename T>
	void printFileHeader(T* pNTHeader) {
		std::cout << "\n\tSignature: " << std::hex << pNTHeader->Signature;

		std::cout << "\n\n\tFILE HEADER:\n\t---------------\n";
		std::cout << "\n\t\tMachine: " << std::hex << pNTHeader->FileHeader.Machine;
		std::cout << "\n\t\tNumber of Sections: " << std::hex << pNTHeader->FileHeader.NumberOfSections;
		std::cout << "\n\t\tFile Creation Time Stamp: " << std::hex << pNTHeader->FileHeader.TimeDateStamp;
		std::cout << "\n\t\tSize of Optional Header: " << std::hex << pNTHeader->FileHeader.SizeOfOptionalHeader;
	}

	template <typename T>
	void printOptionalHeader(T optionalHeader) {

		std::cout << "\n\n\tOptional Header:\n\t---------------\n";
		std::cout << "\n\t\tMagic Number: " << std::hex << optionalHeader.Magic;
		std::cout << "\n\t\tMajor Linker Version: " << std::hex << static_cast<int>(optionalHeader.MajorLinkerVersion);
		std::cout << "\n\t\tMinor Linker Version: " << std::hex << static_cast<int>(optionalHeader.MinorLinkerVersion);
		std::cout << "\n\t\tSize Of Code: " << std::hex << optionalHeader.SizeOfCode;
		std::cout << "\n\t\tSize Of Initialized Data: " << std::hex << optionalHeader.SizeOfInitializedData;
		std::cout << "\n\t\tSize Of Uninitialized Data: " << std::hex << optionalHeader.SizeOfUninitializedData;
		std::cout << "\n\t\tAddress Of Entry Point: " << std::hex << optionalHeader.AddressOfEntryPoint;
		std::cout << "\n\t\tBase Of Code: " << std::hex << optionalHeader.BaseOfCode;
		std::cout << "\n\t\tImage Base: " << std::hex << optionalHeader.ImageBase;
		std::cout << "\n\t\tSection Alignment: " << std::hex << optionalHeader.SectionAlignment;
		std::cout << "\n\t\tMajor Operating System Version: " << std::hex << optionalHeader.MajorOperatingSystemVersion;
		std::cout << "\n\t\tMinor Operating System Version: " << std::hex << optionalHeader.MinorOperatingSystemVersion;
		std::cout << "\n\t\tMajor Image Version: " << std::hex << optionalHeader.MajorImageVersion;
		std::cout << "\n\t\tMinor Image Version: " << std::hex << optionalHeader.MinorImageVersion;
		std::cout << "\n\t\tSize Of Image: " << std::hex << optionalHeader.SizeOfImage;
		std::cout << "\n\t\tSize Of Headers: " << std::hex << optionalHeader.SizeOfHeaders;
	}

	void parseDOSHeader(const IMAGE_DOS_HEADER* pDOSHeader) {
		std::cout << "\n\nDOS HEADER:\n---------------\n";
		std::cout << "\n\tMagic Number: " << std::hex << pDOSHeader->e_magic;
		std::cout << "\n\tNew file header offset: " << std::hex << pDOSHeader->e_lfanew;
	}



	void parseNTHeaders(const std::variant<IMAGE_NT_HEADERS32*, IMAGE_NT_HEADERS64*> ntHeader) {
		std::cout << "\n\nNT HEADER:\n---------------\n";


		if (auto header32 = std::get_if<IMAGE_NT_HEADERS32*>(&ntHeader)) {
			printFileHeader(*header32);
			printOptionalHeader((*header32)->OptionalHeader);
		}
		else if (auto header64 = std::get_if<IMAGE_NT_HEADERS64*>(&ntHeader)) {
			printFileHeader(*header64);
			printOptionalHeader((*header64)->OptionalHeader);
		}

		else {
			std::cerr << "\nInvalid NT header\n";
			return;
		}

	}

	void parseSectionHeaders(const std::vector<IMAGE_SECTION_HEADER*>& sectionHeaders) {

		std::cout << "\n\nSECTION HEADERS:\n---------------\n";
		for (auto& sectionHeader: sectionHeaders) {
			std::cout << "\n\n\t" << std::string(reinterpret_cast<const char*>(sectionHeader->Name), 8) << ":\n\t---------------\n";
			std::cout << "\n\t\tVirtual Address: " << std::hex << sectionHeader->VirtualAddress;
			std::cout << "\n\t\tVirtual Size: " << std::hex << sectionHeader->Misc.VirtualSize;
			std::cout << "\n\t\tRaw data pointer: " << std::hex << sectionHeader->PointerToRawData;
			std::cout << "\n\t\tSize of raw data: " << std::hex << sectionHeader->SizeOfRawData;

		}
	}

	void parseExportTable(const std::vector<std::pair<std::string_view, uintptr_t>>& exportTable) {

		std::cout << "\n\nExported Functions:\n---------------\nFunction Name:\t\tAddress\n\n";

		if (exportTable.empty()) {
			std::cout << "\n\nThe PE does not export any functions\n";
			return;
		}

		for (auto& pair : exportTable) {
			std::cout << pair.first << "\t\t" << pair.second << '\n';
		}

	}

	void parseImportTable(const std::vector<PEParser::ImportTable>& importTable) {

		
		std::cout << "\n\nImported Functions:\n---------------\n";

		if (importTable.empty()) {
			std::cout << "\n\nThe PE does not import any functions\n";
			return;
		}

		for(auto& importTableEntry: importTable) {
			std::cout << "\n\n\tDLL Name: " << importTableEntry.dllName << "\n\t---------------\n";
			std::cout << "\n\t\tIAT: " << std::hex << importTableEntry.iatOffset;

			for (auto& funcEntry : importTableEntry.functionData) {
				std::cout << "\n\t\tFunction Name: " << funcEntry->Name;
			}
		}
	}

	
}
int wmain(int argc, wchar_t* argv[]) {

	if (argc != 2) {
		std::wcerr << L"Usage:\n\t" << argv[0] << L" fileName\n";
		return EXIT_FAILURE;
	}
	try {
		PEParser::PEParser peParser{ std::wstring(argv[1]) };
		parseDOSHeader(peParser.getImageDosHeader());
		parseNTHeaders(peParser.getNTHeader());
		parseSectionHeaders(peParser.getSectionHeaderAddress());
		parseExportTable(peParser.getExportTable());
		parseImportTable(peParser.getImportTable());
	}
	catch (const std::exception& e) {
		std::cerr << e.what() << '\n';
	}
	
	
}