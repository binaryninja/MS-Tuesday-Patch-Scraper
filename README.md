# README.md for the Patch Tuesday Info Tool

## Overview
The Patch Tuesday Info Tool is a Python-based utility designed to extract and report on vulnerabilities and updates for Microsoft products, specifically focusing on the regular updates released on Patch Tuesday. It retrieves data from Microsoft's security update guide, parses the information, and presents it in a user-friendly format.

## Modules
The tool is divided into several modules, each with a specific function:

### 1. main.py
The main script orchestrates the overall functionality, combining elements from other modules to execute the program's core logic.

### 2. data_retrieval.py
Handles the retrieval of data from Microsoft's API, specifically fetching the HTML data for processing.

### 3. data_parsing.py
Responsible for parsing the HTML data retrieved from the API. It structures the data into manageable Python objects for easier manipulation.

### 4. cli_parser.py
Manages command-line interface interactions, parsing the arguments and options provided by the user.

### 5. logging_display.py
Contains functions for logging and displaying messages, errors, and other outputs to the user.

## Features
The tool provides various features including:

- Listing vulnerabilities and updates for specified products.
- Filtering results by product, vulnerability, or date.
- Detailed vulnerability reports including severity, impact, and more.
- Ability to specify a date range or a specific year for filtering results.

## Usage
To use the tool, run the `main.py` script with the desired command-line arguments. The available options include:

- `-V`, `--vulns`: Specify vulnerabilities to detail (can be repeated).
- `-p`, `--products`: Specify product names (can be repeated).
- `-m`, `--months`: Specify the Patch Tuesday month(s) (can be repeated).
- `-y`, `--years`: Specify a year, which will be expanded into months (can be repeated).
- `--list-products`: List all available products.
- `--brief`: Display a summary of the information.
- `-v`, `--verbose`: Increment verbosity for more detailed output.

Example command:
```bash
python main.py --products "Windows 11 Version 22H2 for x64-based Systems" --months 2023-Jan
```

## Dependencies
- Python 3.10
- `requests`
- `bs4` (BeautifulSoup)

## Installation
Ensure Python 3.10 is installed along with the required packages. Clone or download this repository and run `main.py` with Python.

## License
This tool is open-source and free to use.