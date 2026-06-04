# FortiGate Log Processing Script
## Overview
This PowerShell script provides a unified workflow for processing raw log data extracted from FortiGate devices. It integrates with the Fortinet `log_reader.jar` utility to extract, transform, and organise log data into structured, analysis-ready CSV files.
The script is designed to support digital forensic investigations by:  
- Standardising log processing workflows  
- Reducing manual data handling  
- Producing consistent, chronologically ordered datasets  
- Enabling easy ingestion into tools such as Timesketch

## Features
- Recursive extraction of FortiGate raw log data using `log_reader.jar`  
- Automated organisation of extracted logs by type  
- Regex-based parsing and conversion to structured CSV format  
- Predefined schemas for key log types  
- Parallelised CSV merge for performance on large datasets  
- Built-in logging (console + file)  
- Duplicate processing prevention via tracking file  
- README generation summarising processed log types  

## Requirements
- Windows environment  
- PowerShell 5.1 or later  
- Java Runtime Environment (JRE) available in `PATH`  
- Fortinet `log_reader.jar` tool (available as part of this repo)  
- Administrative privileges (recommended)  
- `Out-GridView` support (used for host selection UI)

## Installation
1. Clone or download this repository:  
   `git clone https://github.com/janekpstudentuad/lz4_reader`
2. Ensure the following are configured in the script:  
  - Path to `log_reader.jar`  
  - Base case directory (`$basedirectory`)
3. Verify java is installed:  
  `java -version`

## Usage
Run the script interactively:  
```
cd <script_directory>
.\lz4_processing.ps1
```
⚠️ The script should be run as Administrator to avoid file permission errors

## Workflow
The script guides the user through:  
1. **Case Selection**  
Choose a case directory from the configured base path  
2. **Path Confirmation**  
Confirm derived Working (input) and Analysis (output) paths  
3. **Host Selection**  
Select one or more hosts using an interactive grid view  
4. **Processing Execution**
- Extract logs  
- Categorise by type  
- Convert to CSV  
- Merge outputs per log type

## Expected Input Structure
```
<BaseDirectory>
└── <CaseName>
    ├── Working
    │   ├── <Host1>
    │   │   └── <Collection> (must include "fortigate")
    │   ├── <Host2>
    │       └── <Collection>
    └── Analysis
```
### Notes:
- Raw logs must be **uncompressed**
- Collection directory names must contain "**fortigate**" (case-insensitive)

## Output structure
```
Analysis\
└── FortigateLogs\
    └── <Host>\
        ├── TrafficLogs\
        ├── WebLogs\
        ├── EventLogs\
        ├── ...
        ├── ProcessedLogs\
        └── merged CSV files
```
Additional outputs:  
- Processing log → `Analysis\Processing Logs\`  
- README summary file per host

## Supported Log Types
Schemas are currently defined for:  
- Traffic Logs  
- Web Logs  
- Event Logs  
- IPS Logs  
- Risk Logs  
- SSL Logs  
- Anomaly Logs  

Logs not matching known patterns are placed in `UnidentifiedLogs\`

## Limitations
- Hardcoded paths for base directory and `log_reader.jar`  
- Requires Java and external Fortinet tooling  
- Interactive execution only (not automation-ready)  
- Strict directory structure assumptions  
- Filename-based log classification  
- Limited schema coverage for some log types  
- Regex-based parsing may not handle malformed entries  
- No automatic retry or recovery for failed processing steps  
- Performance may degrade on very large datasets  
- No built-in validation of output completeness or integrity

## Reprocessing Data
The script prevents duplicate processing using a tracking file (`processed_files.txt`)  

To reprocess logs:  
- Delete the tracking file, or remove specific entries from it  
- Clear previously generated output files if needed

## Forensic Considerations
- Original raw log files are not modified  
- CSV output is a transformed representation of the data  
- No hashing or integrity verification is performed  
- Findings should be validated against original source logs where required

## Logging
The script generates detailed logs including:  
- Processing steps  
- Warnings  
- Errors  

Log files are stored in `Analysis\Processing Logs\`

## Output Naming Convention
Merged CSV files follow `<Hostname>_<LogType>_merged_fortigate_logs_<timestamp>.csv`

## Future Improvements
- Expanded schema coverage for additional log types  
- Non-interactive (CLI-driven) execution mode  
- Input validation and schema auto-detection  
- Integrated hashing and integrity checks  
- Performance optimisation for very large datasets

## Author
**Jane Kocan-Payne**  
Security Analyst (DFIR)
