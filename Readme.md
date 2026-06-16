# PE Parser

A simple Portable Executable parser that extracts and displays information from Windows executables and DLLs.

## Features

* Parses DOS headers
* Parses NT headers
* Displays file and optional header information
* Enumerates PE sections
* Enumerates exported functions
* Enumerates imported DLLs and functions

## Requirements

* Windows
* Visual Studio 2026

## Building

### 1. Clone the Repository

```cmd
git clone https://github.com/gold-totem/PEParser.git
cd PEParser
```

### 2. Build Using MSBuild

Open a Visual Studio Developer Command Prompt and run:

```cmd
msbuild PEParser.sln /p:Configuration=Release /p:Platform=x64
```

## Usage

```cmd
ParsePE.exe <path-to-file>
```

Example:

```cmd
ParsePE.exe ParsePE.exe
```
