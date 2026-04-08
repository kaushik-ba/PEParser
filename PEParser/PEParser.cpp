#include <Windows.h>
#include <iostream>
#include "PEParser.h"
#include <string>

namespace PEParser {
	PEParser::PEParser(std::wstring_view pePath) {
		hDLLFile = CreateFileW(pePath.data(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hDLLFile == INVALID_HANDLE_VALUE) {
			throw std::runtime_error("Initialization failed, CreateFileA returned: " + std::to_string(GetLastError()));
		}
		hMapping = CreateFileMappingW(hDLLFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
		if (!hMapping) {
			CloseHandle(hDLLFile);
			throw std::runtime_error("Initialization failed, CreateFileMappingA returned: " + std::to_string(GetLastError()));
		}
		base = reinterpret_cast<BYTE*>(MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0));
		if (!base) {
			CloseHandle(hDLLFile);
			CloseHandle(hMapping);
			throw std::runtime_error("Initialization failed, MapViewOfFile returned: " + std::to_string(GetLastError()));
		}
		pDOSHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(base);

		if (pDOSHeader->e_magic != IMAGE_DOS_SIGNATURE) {
			throw std::runtime_error("Invalid DOS signature");
		}

		IMAGE_NT_HEADERS32* pNTHeader32 = reinterpret_cast<IMAGE_NT_HEADERS32*>(base + pDOSHeader->e_lfanew);
		pFileHeader = reinterpret_cast<IMAGE_FILE_HEADER*>(&(pNTHeader32->FileHeader));
		WORD* bitType = reinterpret_cast<WORD*>(&(pNTHeader32->OptionalHeader));

		if (*bitType == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			peType = PEType::PE64;
			IMAGE_NT_HEADERS64* pNTHeader64 = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + pDOSHeader->e_lfanew);

			pNTHeader = pNTHeader64;

			
			pExportTable = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + pNTHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			importDirectoryTable = reinterpret_cast<uintptr_t>(base + pNTHeader64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		}
		else if (*bitType == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
			peType = PEType::PE32;
			pNTHeader = pNTHeader32;

			pExportTable = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
			importDirectoryTable = reinterpret_cast<uintptr_t>(base + pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		}
		else {
			peType = PEType::OTHER;
			throw std::runtime_error("PE is a ROM/invalid image");
		}

		sectionHeaderAddress = reinterpret_cast<uintptr_t>(base + pDOSHeader->e_lfanew + sizeof(pNTHeader32->Signature) + sizeof(IMAGE_FILE_HEADER) + (pNTHeader32->FileHeader.SizeOfOptionalHeader));
		ordinalTable = reinterpret_cast<PUINT16>(base + pExportTable->AddressOfNameOrdinals);
		pExportAddressTable = reinterpret_cast<DWORD*>(base + pExportTable->AddressOfFunctions);
	}

	const IMAGE_DOS_HEADER* PEParser::getImageDosHeader() const {
		return pDOSHeader;
	}

	const std::variant< IMAGE_NT_HEADERS32*, IMAGE_NT_HEADERS64*> PEParser::getNTHeader() const {
		return pNTHeader;
	}

	const std::vector<IMAGE_SECTION_HEADER*>&  PEParser::getSectionHeaderAddress() {

		if (sectionHeaders.empty()) {
			for (DWORD sectionIndex{ 0 }; sectionIndex < pFileHeader->NumberOfSections; ++sectionIndex) {
				sectionHeaders.emplace_back( reinterpret_cast<IMAGE_SECTION_HEADER*>(sectionHeaderAddress + (sectionIndex * sizeof(IMAGE_SECTION_HEADER))) );
			}

		}
		return sectionHeaders;
		
	}
	
	const std::vector<std::pair<std::string_view, uintptr_t>>& PEParser::getExportTable() {
		if (exportTable.empty()) {

			if (base != reinterpret_cast<BYTE*>(pExportTable)) {

				PUINT32 nameArray{ reinterpret_cast<PUINT32>(base + pExportTable->AddressOfNames) };
				for (UINT32 index = 0; index < pExportTable->NumberOfNames; index++) {
					UINT32 nameRVA{ nameArray[index] };
					char* funcName{ (char*)(base + nameRVA) };
					DWORD ordinal{ ordinalTable[index] };
					uintptr_t functionAddress{ static_cast<uintptr_t>(pExportAddressTable[ordinal]) };
					exportTable.emplace_back(std::make_pair(funcName, functionAddress));
				}
			}
			
		}

		return exportTable;
	}

	const std::vector<ImportTable>& PEParser::getImportTable() {

		if (importDirectoryTable == reinterpret_cast<uintptr_t>(base)) {
			return importTable;
		}


		//TODO: move on struct ImportTable
		if (importTable.empty()) {
			IMAGE_IMPORT_DESCRIPTOR* pImportDirectoryEntry = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(importDirectoryTable);


			while (pImportDirectoryEntry->Characteristics) {
				struct ImportTable importTablestruct;

				importTablestruct.dllName =  reinterpret_cast<char*>(base + pImportDirectoryEntry->Name);
				importTablestruct.iatOffset = pImportDirectoryEntry->FirstThunk;
				
				if (peType == PEType::PE64) {
					uint64_t* pImportLookupTable = reinterpret_cast<uint64_t*>(base + pImportDirectoryEntry->Characteristics);
					int index = 0;
					uint64_t iltEntry{ pImportLookupTable[index] };
					while (iltEntry != 0) {
						if (!(IMAGE_ORDINAL_FLAG64 & iltEntry)) {
							importTablestruct.functionData.emplace_back(reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + iltEntry) );
						}
						index++;
						iltEntry = pImportLookupTable[index];
					}

				}
				else {
					uint32_t* pImportLookupTable = reinterpret_cast<uint32_t*>(base + pImportDirectoryEntry->Characteristics);
					int index = 0;
					uint32_t iltEntry{ pImportLookupTable[index] };
					while (iltEntry != 0) {
						if (!(IMAGE_ORDINAL_FLAG64 & iltEntry)) {
							importTablestruct.functionData.emplace_back(reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + iltEntry));
						}
						index++;
						iltEntry = pImportLookupTable[index];
					}
				}
				pImportDirectoryEntry++;
				importTable.emplace_back(importTablestruct);
			}
		}
		return importTable;
	}

	bool PEParser::searchExportTable(std::string_view functionName, std::uintptr_t& functionAddress) const {

		if (peType == PEType::OTHER) {
			return false;
		}
		//TODO: use binary search
		PUINT32 nameArray{ reinterpret_cast<PUINT32>(base + pExportTable->AddressOfNames) };
		
		for (UINT32 index = 0; index < pExportTable->NumberOfNames; index++) {
			
			UINT32 nameRVA = nameArray[index];
			char* funcName = (char*)(base + nameRVA);
			if (std::strcmp(functionName.data(), funcName) == 0) {
				
				DWORD ordinal = ordinalTable[index];
				functionAddress = static_cast<uintptr_t>(pExportAddressTable[ordinal]);
				return true;
			}
		}
		return false;

	}

	bool PEParser::searchImportTable(std::string_view functionName) const {
		if (peType == PEType::OTHER) {
			return false;
		}

		IMAGE_IMPORT_DESCRIPTOR* pImportDirectoryEntry = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(importDirectoryTable);

		//TODO: use binary search
		while (pImportDirectoryEntry->Characteristics) {

			if (peType == PEType::PE64) {
				uint64_t* pImportLookupTable = reinterpret_cast<uint64_t*>(base + pImportDirectoryEntry->Characteristics);
				int index = 0;
				uint64_t iltEntry{ pImportLookupTable[index] };
				while (iltEntry != 0) {
					if (!(IMAGE_ORDINAL_FLAG64 & iltEntry)) {
						IMAGE_IMPORT_BY_NAME* nameTableEntry{ reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + iltEntry) };
						if (std::strcmp(functionName.data(), nameTableEntry->Name) == 0) {
							return true;
						}
					}
					index++;
					iltEntry = pImportLookupTable[index];
				}

			}
			else {
				uint32_t* pImportLookupTable = reinterpret_cast<uint32_t*>(base + pImportDirectoryEntry->Characteristics);
				int index = 0;
				uint32_t iltEntry{ pImportLookupTable[index] };
				while (iltEntry != 0) {
					if (!(IMAGE_ORDINAL_FLAG64 & iltEntry)) {
						IMAGE_IMPORT_BY_NAME* nameTableEntry{ reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + iltEntry) };
						if (std::strcmp(functionName.data(), nameTableEntry->Name) == 0) {
							return true;
						}
					}
					index++;
					iltEntry = pImportLookupTable[index];
				}
			}
			pImportDirectoryEntry++;
		}
		return false;
	}
	
	PEParser::~PEParser() {
		if (base) UnmapViewOfFile(base);
		if (hMapping) CloseHandle(hMapping);
		if (hDLLFile != INVALID_HANDLE_VALUE) CloseHandle(hDLLFile);
	}
}