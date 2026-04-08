#pragma once
#include <Windows.h>
#include <string_view>
#include <variant>
#include <optional>
#include <vector>
#include <map>
namespace PEParser {
	struct ImportTable {
		std::string_view dllName;
		DWORD iatOffset{ 0 };
		std::vector<const IMAGE_IMPORT_BY_NAME*> functionData;
	};
	class PEParser {
	public:

		bool searchExportTable(std::string_view functionName, std::uintptr_t& functionAddress) const;
		bool searchImportTable(std::string_view functionName) const;

		const IMAGE_DOS_HEADER* getImageDosHeader() const;
		const std::variant<IMAGE_NT_HEADERS32*, IMAGE_NT_HEADERS64*> getNTHeader() const;
		const std::vector<IMAGE_SECTION_HEADER*>& getSectionHeaderAddress();
		const std::vector<std::pair<std::string_view, uintptr_t>>& getExportTable();
		const std::vector<ImportTable>& getImportTable();
		PEParser(std::wstring_view pePath);
		~PEParser();

	private:
		enum class PEType {
			PE32,
			PE64,
			OTHER
		} peType{PEType::OTHER};

		HANDLE hDLLFile{ INVALID_HANDLE_VALUE };
		HANDLE hMapping{ NULL };
		BYTE* base{ nullptr };

		IMAGE_DOS_HEADER* pDOSHeader{ nullptr };
		IMAGE_FILE_HEADER* pFileHeader{ nullptr };
		std::variant< IMAGE_NT_HEADERS32*, IMAGE_NT_HEADERS64*> pNTHeader;
		IMAGE_EXPORT_DIRECTORY* pExportTable{ nullptr };
		uintptr_t sectionHeaderAddress{ 0 };
		uintptr_t importDirectoryTable{ 0 };
		PUINT16 ordinalTable{0};
		DWORD* pExportAddressTable{ nullptr };

		std::vector<IMAGE_SECTION_HEADER*> sectionHeaders;
		std::vector<std::pair<std::string_view, uintptr_t>> exportTable;
		std::vector<ImportTable> importTable;
	};
}
