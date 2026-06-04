<#
.SYNOPSIS
    Processes raw data files from Fortigate devices for forensic investigation.

.DESCRIPTION
    This script makes use of the log_reader.jar tool to extract data from multiple raw data files exported from Fortigate devices.
    The processing of these files includes data extraction, relocation of output files, removal of junk output data, and conversion to/merging of CSV files, categorised by log type.
    On completion, merged CSV files can be imported into Timesketch for further analysis.

.EXAMPLE
    .\lz4_reader.ps1

.LINK
    https://community.fortinet.com/t5/FortiAnalyzer/Technical-Tip-Transferring-historical-logs-from-a-FortiGate-hard/ta-p/193850

.NOTES
    26/04/26    Script created (JKP)
    27/05/26    Version 1.0 ready for production. Functionality:
        * Dependency check prior to script run
        * User-confirmed suitability check prior to script run
        * Context-based logging
        * User-driven selection of case and raw data directory
        * Extraction of data from raw logs exported from Fortigate devices
        * Tracking file for processed file names
        * Recursive directory searching for all logs
        * Extracted TXT files moved to Analysis folder
        * Junk output folders deleted
        * Logs categorised according to name and moved to relevant log type subdirectories
        * TXT files converted to .csv format
        * Processed TXT files moved to Processed Logs subdirectory
        * CSV files grouped into chunks per log type and merged
        * Merged CSV files moved to parent Analysis folder
        * README file produced to assist with analysis
        * Log file moved to Processing Logs directory
        * All required directories created when necessary
#>

###################################
# Set variables
###################################

# Force classic progress view
$PSStyle.Progress.View = 'Classic'

# Java tool location
$jar  = "D:\Tools\LZ4Reader\lz4_reader\log_reader.jar" # Change as necessary

# Base directory for files
$basedirectory = 'F:\' # Change as necessary

# File handling
$excludeddirs = @( 'Processing Logs', 'ProcessedLogs', 'merge_temp' )

# Initialise variables for logging
$logroot = "C:\Temp"
$timestamp = Get-Date -Format 'ddMMyyyy_HHmmss'
$logfile = "lz4reader_$timestamp.log"
$logfilepath = Join-Path $logroot $logfile
$analyst = "$env:USERDOMAIN\$env:USERNAME"

# Processed log directories
$logdirs = @(
    'TrafficLogs',
    'WebLogs',
    'EventLogs',
    'IPSLogs',
    'RiskLogs',
    'SSLLogs',
    'AnomalyLogs',
    'UnidentifiedLogs'
)

# Processed logs column selections
$logschemas = @{
    AnomalyLogs = @(
        'datetime',
        'type',
        'vd',
        'msg',
        'srcport',
        'qtype',
        'qname',
        'qclass',
        'eventtype',
        'srccountry',
        'dstcountry',
        'srcmac',
        'dstinf',
        'user',
        'srcip',
        'group',
        'error',
        'action',
        'profile',
        'srcintfrole',
        'level'
    )
    EventLogs = @(
        'datetime',
        'type',
        'vd',
        'msg',
        'remip',
        'ip',
        'action',
        'level',
        'logdesc',
        'subtype'
    )
    RiskLogs = @(
        'datetime',
        'type',
        'vd',
        'msg',
        'applist',
        'apprisk',
        'dstip',
        'eventtype',
        'srccountry',
        'direction',
        'dstcountry',
        'scertname',
        'service',
        'scertissuer',
        'dstinf',
        'srcip',
        'hostname',
        'policytype',
        'app',
        'appcat',
        'url',
        'dstport',
        'action',
        'srcport',
        'level'
    )
    SSLLogs = @(
        'datetime',
        'type',
        'vd',
        'msg',
        'srcport',
        'eventtype',
        'srccountry',
        'dstcountry',
        'service',
        'srcip',
        'sni',
        'hostname',
        'srcintf',
        'eventsubtype',
        'action',
        'profile',
        'level'
    )
    TrafficLogs = @(
        'datetime',
        'type',
        'vd',
        'msg',
        'srcport',
        'rcvdbyte',
        'dstip',
        'srccountry',
        'dstcountry',
        'srcmac',
        'user',
        'service',
        'srcip',
        'transip',
        'sentbyte',
        'policyname',
        'appcat',
        'srcintf',
        'srchwvendor',
        'action',
        'level'
    )
    WebLogs = @(
        'datetime',
        'type',
        'vd',
        'msg',
        'applist',
        'apprisk',
        'dstip',
        'eventtype',
        'srccountry',
        'direction',
        'dstcountry',
        'scertname',
        'service',
        'scertissuer',
        'dstinf',
        'srcip',
        'hostname',
        'policytype',
        'app',
        'appcat',
        'url',
        'dstport',
        'action',
        'srcport',
        'level'
    )
}

###################################
# Local function(s)
###################################
### Set config for logging
function Write-Log {
    param (
        [Parameter(Mandatory)]
        [ValidateSet('INFO', 'ERROR', 'WARN', 'SUCCESS')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message
    )

    # Timestamp for log entry
    $timestamp = Get-Date -Format 'dd/MM/yyyy HH:mm:ss'
    
    # Console output (preserves new line characters)
    $console = "`n[$Level] $Message"

    # File output (force entries to a single line)
    $fileMessage = ($Message -replace '\r?\n+', ' ').Trim()
    $entry = "[$Level] $timestamp $fileMessage"

    # Event categorisation based on coloured console output
    switch ($Level) {
        'INFO'      { Write-Host $console -ForegroundColor White }
        'SUCCESS'   { Write-Host $console -ForegroundColor Green }
        'WARN'      { Write-Host $console -ForegroundColor Yellow }
        'ERROR'     { Write-Host $console -ForegroundColor Red }
    }

    # Structure log file
    $script:LogWriter.WriteLine($entry)
    $script:LogWriter.Flush()
}

### Set processing configuration
function Set-ProcessingConfiguration {
    param (
        [Parameter (Mandatory)]
        [string]$BaseDirectory
    )
    # Select the appropriate case
    Write-Host "`nWhich case are you working on?" -ForegroundColor Cyan 
    $allcases = Get-ChildItem -Path $BaseDirectory
    $x=1
    foreach($case in $allcases){
        Write-Host " $x) $($case.name)" -ForegroundColor Cyan
        $x++
        }
    
    do {
        Write-Host "`nEnter the number before the case name (1, 2, 3, etc...): " -ForegroundColor Cyan -NoNewline
        $caseselection = Read-Host

        $valid = 
            ($caseselection -match '^\d+$') -and
            ([int]$caseselection -ge 1) -and
            ([int]$caseselection -le $allcases.Count)
        
        if (-not $valid) {
            Write-Log -Level ERROR -Message "`nInvalid selection. Please enter a number between 1 and $($allcases.Count)."
        }
    } until ($valid)

        $selectedcase = $allcases[[int]($caseselection - 1)].FullName
        Remove-Variable x -ErrorAction SilentlyContinue
        Write-Log -Level INFO -Message "Working on $selectedcase"

    # Set input folder
    $inputpath = "$selectedcase\Working\"

    # Set output folder
    $outputpath = "$selectedcase\Analysis\"

    # Folder selection confirmation
    Write-Host @"

Input folder: $inputpath 
Output folder: $outputpath
"@ -ForegroundColor Cyan

    Write-Host "`nAre these the correct input and output folders? (y/n) " -ForegroundColor Cyan -NoNewline
    $confirmation = Read-Host
    if ($confirmation -ne "y") {
        Write-Log -Level ERROR -Message "Please rerun this script and select the correct case. Exiting script."
        exit
    }

    # Find the collections for each host. Display grid with hostname, collection name, and full path
    $selectedhosts = Get-ChildItem -Path $inputpath -Depth 1 -Directory | 
        Where-Object { $_.Parent.Name -ne "Working" } | 
        Select-Object @{
            Name = 'Host'
            Expression = { $_.Parent.Name }
        }, 
        @{
            Name = 'Collection'
            Expression = { $_.Name }
        },
        @{
            Name = 'FullPath'
            Expression = { $_.FullName }
        } | Out-GridView -Title "Select Host(s) to Process" -PassThru

    # If grid cancelled by used
    if ($null -eq $selectedhosts) {
        Write-Log -Level ERROR -Message "No hosts selected. Script exiting."
        exit
    } else {
        foreach ($hostname in $selectedhosts) {
            Write-Log -Level INFO -Message "Host: $($hostname.Host) at $($hostname.FullPath) selected."
        }
    }

    return [PSCustomObject]@{
        SelectedCase    = $selectedcase
        InputPath       = $inputpath
        OutputPath      = $outputpath
        Hostnames       = $selectedhosts
    }
}

### Extract data from files in log folders (recursive)
function Extract-Data {
    param (
        [Parameter (Mandatory)]
        [PsCustomObject]$Target,

        [Parameter(Mandatory)]
        [string]$JarPath
    )
    
    # Validate that target folders relate to Fortigate logs
    if ($Target.Collection -notmatch '(?i)fortigate') {
        Write-Log -Level WARN -Message "Skipping host $($Target.Host). Directory does not contain 'fortigate': $($Target.FullPath)"
        return 0
    }

    # Create file to keep track of files already processed
    $trackingfile = Join-Path $Target.FullPath 'processed_files.txt'
    $processed = @{}
    if (Test-Path $trackingfile) {
        Get-Content $trackingfile | Foreach-Object {
            $processed[$_] = $true
        }
    }

    # Get files to be processed
    $files = Get-ChildItem $Target.FullPath -Recurse -File | 
        Where-Object { 
            $_.Name -notmatch '_readable\.txt$' -and
            $_.FullName -ne $trackingfile
        }
    
    # Initialise counters
    $processedcount = 0
    $skippedprocessed = 0
    $skippedempty = 0
    $totalfiles = $files.Count
    
    # Use .jar file to extract data from all child directories in Fortigate logs directory (recursive)
        Write-Log -Level INFO -Message "Found $totalfiles files to process for $($Target.Host)"
    foreach ($file in $files) {
        # Skip zero-byte files
        if ($file.Length -eq 0) {
            $skippedempty++
            Write-Log -Level WARN -Message "Skipping empty file: $($file.FullName)"
            continue
        }

        # Skip already processed files
        if ($processed.ContainsKey($file.Name)) {
            Write-Log -Level WARN -Message "Skipping previously processed file: $($file.Name)"
            $skippedprocessed++
            continue
        }

        try {
            & java -jar $JarPath $file.FullName
            # Record as processed
            $processed[$file.Name] = $true
            Add-Content -Path $trackingfile -Value $file.Name
            $processedcount++
            $completedfiles = $processedcount + $skippedprocessed + $skippedempty
            Write-Log -Level INFO -Message "Extraction progress: processing $($file.Name), file $completedfiles/$totalfiles"
        }
        catch {
            Write-Log -Level ERROR -Message "FAILED: $($file.FullName)"
        }
    }
    Write-Log -Level INFO -Message "Extraction summary for $($Target.Host):"
    Write-Log -Level INFO -Message "  Processed $processedcount files"
    Write-Log -Level INFO -Message "  $skippedempty empty files skipped"
    Write-Log -Level INFO -Message "  $skippedprocessed previously processed files skipped"
    return $processedcount
}

### Output file cleanup
function Invoke-OutputCleanup {
    param (
        [Parameter (Mandatory)]
        [PsCustomObject]$Target,

        [Parameter (Mandatory)]
        $HostOutputDir
    )

    # Recursively search for any files ending in "readable.txt" and move to an appropriate Analysis folder
    $files = Get-ChildItem $Target.FullPath -Recurse -File -Filter '*_readable.txt'
    foreach ($file in $files) {
        Write-Log -Level SUCCESS -Message "$($file.Name) moved to $($HostOutputDir)"
        Move-Item -LiteralPath $file.FullName -Destination $HostOutputDir -Force
    }

    # Find all directories starting with "disk-" and forcibly remove (recursive)
    foreach ($dir in Get-ChildItem -Path $Target.FullPath -Recurse -Directory) {
        if ($dir.Name -like 'disk-*') {
            Write-Log -Level SUCCESS -Message "$($dir.FullName) and contents deleted."
            Remove-Item -LiteralPath $dir.FullName -Recurse -Force
        }
    }
}

### Helper function for directory creation
function Ensure-Directory {
    param([string]$Path)

    # Check if a directory exists; create if not
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -ItemType Directory | Out-Null
        Write-Log -Level SUCCESS -Message "Directory created: $Path"
    }

    return $Path
}

### Sort output files into directories
function Move-OutputFile {
    param (
        [Parameter (Mandatory)]
        [string]$HostOutputDir        
    )

    # Get all CSV files in the host output directory
    $txtfiles = Get-ChildItem -Path $HostOutputDir -File -Filter '*_readable.txt'

    # Define destination folders for files
    foreach ($file in $txtfiles) {
        switch -Wildcard ($file.Name) {
            # Event logs
            'disk-elog*' {
                $destdir = Join-Path $HostOutputDir 'EventLogs'
            }

            #Anomaly logs
            'disk-olog*' {
                $destdir = Join-Path $HostOutputDir 'AnomalyLogs'
            }

            # IPS logs
            'disk-plog*' {
                $destdir = Join-Path $HostOutputDir 'IPSLogs'
            }

            # Risk logs
            'disk-rlog*' {
                $destdir = Join-Path $HostOutputDir 'RiskLogs'
            }

            # SSL logs
            'disk-ssllog*' {
                $destdir = Join-Path $HostOutputDir 'SSLLogs'
            }

            # Traffic logs
            'disk-tlog*' {
                $destdir = Join-Path $HostOutputDir 'TrafficLogs'
            }

            # Web logs
            'disk-wlog*' {
                $destdir = Join-Path $HostOutputDir 'WebLogs'
            }

            # Unmatched log types
            default {
                $destdir = Join-Path $HostOutputDir 'UnidentifiedLogs'
            }
        }

    # Create destination folder if required
    Ensure-Directory -Path $destdir | Out-Null

    # Move file
    Move-Item -LiteralPath $file.FullName -Destination $destdir -Force
    Write-Log -Level SUCCESS -Message "Moved $($file.Name) to $(Split-Path $destdir -Leaf)"
    }
}

### Convert .txt output files to .csv
function Convert-OutputFileToCsv {
    param (
        [Parameter (Mandatory)]
        [string]$InputFile,

        [Parameter (Mandatory)]
        [string]$OutputFile,

        [Parameter(Mandatory)]
        [string]$LogType
    )

    $objects = foreach ($line in Get-Content $InputFile) {
        $hash = @{}        
        $regex = [regex]'(\w+)=(".*?"|\S+)'
        foreach ($match in $regex.Matches($line)) {
            $key = $match.Groups[1].Value
            $value = $match.Groups[2].Value.Trim('"')
            $hash[$key] = $value
        }

        # datetime column creation        
        if ($hash.ContainsKey('date') -and $hash.ContainsKey('time')) {
            $hash['datetime'] = [datetime]::ParseExact(
                "$($hash['date']) $($hash['time'])",
                "yyyy-MM-dd HH:mm:ss",
                $null
            )
        }

        [PSCustomObject]$hash
    }

    # Apply correct column selection schema for log type
    $schema = $logschemas[$LogType]
    $objects = @($objects)

    if (-not $schema) {
        Write-Log -Level WARN -Message "No schema defined for $LogType, using fallback"
        $schema = $objects[0].PSObject.Properties.Name
    }

    # Define fields that are being renamed
    $renamedfields = @('type', 'vd', 'msg')

    # Remove renamed fields from schema
    $filteredschema = $schema | Where-Object { $_ -notin $renamedfields }

    $selectproperties = @(
        $filteredschema
        @{Name='timestamp_desc'; Expression={ $_.type }}
        @{Name='host'; Expression={ $_.vd }}        
        @{
            Name='message'
            Expression={
                if ($_.msg) {
                    $_.msg
                } else {
                    "$($_.action.ToUpper()) $($_.srcip):$($_.srcport) -> $($_.dstip):$($_.dstport) ($($_.service)) [$($_.policyname)]"
                }
            }
        }

    )

    $objects |
        Where-Object { $_.datetime } |
        Sort-Object -Property datetime |
        Select-Object -Property $selectproperties |
        Export-Csv -Path $OutputFile -NoTypeInformation
}

### Function for initiating TXT => CSV pipeline
function Invoke-ConversionPipeline {
    param(
        [string]$LogDirectory,
        [string]$LogType
    )

    # Get files to convert
    $files = Get-ChildItem -Path $LogDirectory -Filter '*_readable.txt'
    $dirobject = Get-Item $LogDirectory
    
    # Initiate counters
    $total = $files.Count
    $converted = 0

    # Perform conversion on files; print progress to screen
    foreach ($file in $files) {
        $converted++
        $csv = [System.IO.Path]::ChangeExtension($file.FullName, '.csv')
        Convert-OutputFileToCsv -InputFile $file.FullName -OutputFile $csv -LogType $LogType
        Write-Log -Level SUCCESS -Message "Converted $($file.Name) ($converted/$total in $($dirobject.Name))"
    }
}

### Function for initiating CSV merge pipeline
function Invoke-MergePipeline {
    param (
        [Parameter(Mandatory)]
        [string]$HostOutputDir,

        [Parameter(Mandatory)]
        [string]$HostName,
        
        [Parameter(Mandatory)]
        [string[]]$LogDirs,

        [Parameter(Mandatory)]
        [string[]]$ExcludedDirectories
    )

    foreach ($dir in $LogDirs) {
        $fullpath = Join-Path $HostOutputDir $dir
        if (-not (Test-Path $fullpath)) {
            continue
        }
        
        # Get CSV files (excluding merged outputs)
        $csvfiles = Get-ChildItem -Path $fullpath -File -Filter '*.csv' | Where-Object { $_.Name -notlike '*merged_fortigate_logs*' }
        if ($csvfiles.Count -le 1) {
            Write-Log -Level INFO -Message "Skipping merge for $dir (only $($csvfiles.Count) file present)"
            continue
        }

        # Commence merge operation
        Write-Log -Level INFO -Message "Starting merge for $dir"
        Merge-HostCsvFiles-Parallel -HostOutputDir $fullpath -HostName "$HostName`_$($dir -replace ' ', '_')"  -ExcludedDirectories $excludeddirs
        Write-Log -Level INFO -Message "Completed merge for $dir"
    }
}

### Merge individual log files into one per host
function Merge-HostCsvFiles {
    param (
        [Parameter(Mandatory)]
        [string]$HostOutputDir,

        [Parameter(Mandatory)]
        [string]$HostName,

        [Parameter(Mandatory)]
        $ExcludedDirectories
    )

    # Get all CSV files in subdirectories (exclude root and processed folders)
    $csvfiles = Get-ChildItem -Path $HostOutputDir -Recurse -File -Filter '*.csv' | Where-Object { $_.Directory.Name -notin $ExcludedDirectories }
    if (-not $csvfiles) {
        Write-Log -Level INFO -Message "No CSV files found to merge for $HostName"
        return
    }

    # Skip merging if only one output file
    if ($csvfiles.Count -eq 1) {
        Write-Log -Level INFO -Message "Only one CSV file found for $HostName - skipping merge"
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $outputfile = Join-Path $HostOutputDir "$HostName`_merged_fortigate_logs_$timestamp.csv"
        Copy-Item -LiteralPath $csvfiles[0].FullName -Destination $outputfile -Force
        Write-Log -Level SUCCESS -Message "Single file copied as merged output: $outputfile"
        return
    }

    # Initiate counter for final merge progress
    $totalrows = 0
    $processedrows = 0
    foreach ($file in $csvfiles) {
        $linecount = (Get-Content $file.FullName | Measure-Object -Line).Lines
        if ($linecount -gt 0) {
            $totalrows += ($linecount - 1) # Subtract header row
        }
    }
    
    # Commence merge operation
    Write-Log -Level INFO -Message "Merging $($csvfiles.Count) CSV files for $HostName"

    # Define output file
    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $outputfile = Join-Path $HostOutputDir "$HostName`_merged_fortigate_logs_$timestamp.csv"

    # Create readers for each file
    $readers = @()

    # Create counter variable
    $totalfiles = $csvfiles.Count
    
    # Get files for readers
    foreach ($file in $csvfiles) {
        $reader = [System.IO.File]::OpenText($file.FullName)
        
        # Skip header row in each file
        $header = $reader.ReadLine()
        
        # Read each file line by line to parse to writer
        $line = $reader.ReadLine()
        if ($line) {
            $row = $line | ConvertFrom-Csv -Header ($header -split ',')
            $dt = $null
            if ($row.datetime -and [datetime]::TryParse($row.datetime, [ref]$dt)) {
                $dt = $dt
            } else {
                $dt = [datetime]::MaxValue
            }
            $readers += [PSCustomObject]@{
                Reader = $reader
                CurrentLine = $line
                CurrentDate = $dt
                Header = $header
            }
        }
    }

    # Create writer
    $writer = [System.IO.StreamWriter]::new($outputfile, $false)

    # Write lines parsed from reader
    try {
        #Write header from first file
        $writer.WriteLine($readers[0].Header)

        while ($readers.Count -gt 0) {
            # Get earliest datetime row
            $next = $readers | Sort-Object CurrentDate | Select-Object -First 1

            # Write line
            $writer.WriteLine($next.CurrentLine)

            # Track progress
            $processedrows++
            if ($totalrows -gt 0) {
                $percent = [int](($processedrows / $totalrows) * 100)
                Write-Progress `
                    -Activity "Merging CSV files..." `
                    -Status "$processedrows of $totalrows rows processed" `
                    -PercentComplete $percent
            }

            # Advance that reader
            $line = $next.Reader.ReadLine()

            if ($line) {
                $row = $line | ConvertFrom-Csv -Header ($next.Header -split ',')
                $dt = $null
                if ($row.datetime -and [datetime]::TryParse($row.datetime, [ref]$dt)) {
                    $dt = $dt
                } else {
                    $dt = [datetime]::MaxValue
                }
                $next.CurrentLine = $line
                $next.CurrentDate = $dt
            } else {
                $next.Reader.Close()
                $readers = $readers | Where-Object { $_ -ne $next }
                $completedfiles = $totalfiles - $readers.Count
                $lastupdate = Get-Date
                Write-Log -Level INFO -Message "Merge progress: $completedfiles/$totalfiles files completed at $lastupdate"
            }
        }
    }
    finally {
        $writer.Close()
    }

    Write-Log -Level SUCCESS -Message "Merged CSV created: $outputfile"
}

### Parallel merge individual log files
function Merge-HostCsvFiles-Parallel {
    param (
        [Parameter(Mandatory)]
        [string]$HostOutputDir,

        [Parameter(Mandatory)]
        [string]$HostName,

        [Parameter(Mandatory)]
        $ExcludedDirectories,

        [int]$ChunkSize = 25,
        [int]$MaxParallel = 4
    )

    # Get all CSV files in subdirectories (exclude root and processed folders)
    $csvfiles = Get-ChildItem -Path $HostOutputDir -Recurse -File -Filter '*.csv' | Where-Object { $_.Directory.Name -notin $ExcludedDirectories }
    if (-not $csvfiles) {
        Write-Log -Level INFO -Message "No CSV files found to merge for $HostName"
        return
    }

    # Split files into processing "chunks"
    Write-Log -Level INFO -Message "Parallel merge: splitting $($csvfiles.Count) files into chunks of $ChunkSize"
    $chunks = @()
    for ($i = 0; $i -lt $csvfiles.Count; $i += $ChunkSize) {
        $chunks += ,($csvfiles[$i..([Math]::Min($i + $ChunkSize - 1, $csvfiles.Count - 1))])
    }

    # Create temporary directory for merged chunks
    $tempdir = Join-Path $HostOutputDir "merge_temp"
    Ensure-Directory -Path $tempdir | Out-Null

    $jobs = @()
    $chunkindex = 0
    foreach ($chunk in $chunks) {
        $chunkindex++
        while (@($jobs | Where-Object State -eq 'Running').Count -ge $MaxParallel) {
            Start-Sleep -Seconds 1
        }

        $tempfile = Join-Path $tempdir "chunk_$chunkindex.csv"
        Write-Log -Level INFO -Message "Starting chunk $chunkindex with $($chunk.Count) files"
        try {
            $job = Start-Job -ScriptBlock {
                param($files, $output)

                $writer = [System.IO.StreamWriter]::new($output, $false)

                try {
                    $first = $true
                    foreach ($file in $files) {
                        $lines = [System.IO.File]::ReadLines($file.FullName)

                        if ($first) {
                            foreach ($line in $lines) { $writer.WriteLine($line) }
                            $first = $false
                        } else {
                            $lines | Select-Object -Skip 1 | ForEach-Object {
                                $writer.WriteLine($_)
                            }
                        }
                    }
                }
                finally {
                    $writer.Close()
                }
            } -ArgumentList ($chunk, $tempfile)

            $jobs = @($jobs + $job)
        }
        catch {
            Write-Log -Level ERROR -Message "Failed to start job for chunk $chunkindex"
            throw
        }
    }
    # Wait for all jobs
    Write-Log -Level INFO -Message "Waiting for chunk merges to complete..."
    $jobs | Wait-Job | Out-Null
    $failed = $jobs | Where-Object State -eq 'Failed'
    if ($failed) {
        Write-Log -Level ERROR -Message "$($failed.Count) merge jobs failed"
        throw "Merge failed"
    }
    $jobs | Receive-Job | Out-Null
    $jobs | Remove-Job

    # Check how many chunk outputs were created
    $chunkoutputs = Get-ChildItem -Path $tempdir -Filter '*.csv'
    if ($chunkoutputs.Count -eq 0) {
        Write-Log -Level ERROR -Message "No chunk outputs found in $tempdir"
        return
    }
    if ($chunkoutputs.Count -eq 1) {
        Write-Log -Level INFO -Message "Skipping final merge (single chunk output)"
        $finalfile = $chunkoutputs[0]

        # Generate final merged filename (same convention as normal merge)
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        $newname = "$HostName`_merged_fortigate_logs_$timestamp.csv"
        $newpath = Join-Path $tempdir $newname
        Rename-Item -LiteralPath $finalfile.FullName -NewName $newname
        Write-Log -Level INFO -Message "Renamed single chunk output to merged format: $newname"
        $finalfile = Get-Item $newpath
    } else {
        # Final merge
        Write-Log -Level INFO -Message "Performing final merge..."
        Merge-HostCsvFiles -HostOutputDir $tempdir -HostName $HostName -ExcludedDirectories @()
        
        # Move final output
        $finalfile = Get-ChildItem $tempdir -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (-not $finalfile) {
            Write-Log -Level ERROR -Message "Final merge output not found in $tempdir"
            return
        }
    }
    
    if ((Get-Item $finalfile.FullName).Length -eq 0) {
        Write-Log -Level ERROR -Message "Final merged file is empty!"
        throw "Merge integrity failure"
    }
    
    $parentdir = Split-Path $HostOutputDir -Parent
    Move-Item -LiteralPath $finalfile.FullName -Destination $parentdir -Force

    # Cleanup
    $tries = 0
    $maxtries = 5

    while ($tries -lt $maxtries) {
        try {
            Remove-Item -LiteralPath $tempdir -Recurse -Force -ErrorAction Stop
            break
        } catch {
            $tries++
            Start-Sleep -Seconds 2
            if ($tries -eq $maxtries) {
                Write-Log -Level WARN -Message "Failed to delete $tempdir after $maxtries attempts"
            }
        }
    }
    
    Write-Log -Level SUCCESS -Message "Parallel merge completed for $HostName"
}

### Function to handle all processing
function Invoke-HostProcessing {
    param (
        [PSCustomObject]$Target,
        [string]$Jar,
        [string]$OutputRoot,
        [string]$LogDirs,
        [string]$ExcludedDirectories
    )

    # Remove unwanted error TXT files before processing
    Get-ChildItem -Path $Target.FullPath -Recurse -File -Filter '*.txt' |
        Where-Object { $_.Name -match 'error' } |
        Remove-Item -Force
    
    # Initialise counter for progress reporting
    $processedcount = Extract-Data -Target $Target -JarPath $Jar
    if ($processedcount -eq 0) {
        Write-Log -Level WARN -Message "No new files processed for $($Target.Host). Skipping downstream steps"
        return
    }

    # Define output directory
    $hostoutputdir = Ensure-Directory (Join-Path $OutputRoot $Target.Host)

    # Perform processing
    Invoke-OutputCleanup -Target $Target -HostOutputDir $hostoutputdir
    Move-OutputFile -HostOutputDir $hostoutputdir

    # Check for Unidentified Logs and warn
    $unidentifiedpath = Join-Path $hostoutputdir 'UnidentifiedLogs'

    if (Test-Path $unidentifiedpath) {
        $unidentifiedfiles = Get-ChildItem -Path $unidentifiedpath -Filter '*_readable.txt' -File
        $unidentifiedcount = $unidentifiedfiles.Count
        if ($unidentifiedcount -gt 0) {
            Write-Log -Level WARN -Message "$unidentifiedcount file(s) in UnidentifiedLogs found. These have not been processed as no schema has been specified for their CSV conversion." 
        }
    }

    # Get only directories that actually exist
    $existingdirs = $LogDirs | Where-Object {
        $_ -ne 'UnidentifiedLogs' -and
        (Test-Path (Join-Path $hostoutputdir $_))
    }

    $totaldirs = $existingdirs.Count
    $currentdir = 0

    # Convert per log directory
    foreach ($directory in $existingdirs) {
        $currentdir++
        $fullpath = Join-Path $hostoutputdir $directory
        Invoke-ConversionPipeline -LogDirectory $fullpath -LogType $directory
        Write-Log -Level SUCCESS -Message "Completed conversion of files in $directory. $currentdir/$totaldirs directories completed."
    }
    
    # Move processed TXT files
    $processeddir = Ensure-Directory (Join-Path $hostoutputdir 'ProcessedLogs')
    Get-ChildItem -Path $hostoutputdir -Recurse -Filter '*_readable.txt' | Move-Item -Destination $processeddir -Force
    
    # Merge per log directory
    Invoke-MergePipeline -HostOutputDir $hostoutputdir -HostName $Target.Host -LogDirs $LogDirs -ExcludedDirectories $ExcludedDirectories
    Write-Log -Level SUCCESS -Message "Processing completed from $($Target.Host)."
}

# Produce README for extracted logs
function Make-Readme {
    param (
        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    # Define output file
    $timestamp = Get-Date -Format 'ddMMyyyy_HHmmss'
    $readmepath = Join-Path $OutputPath "README_$timestamp.txt"

    # Get all directories recursively
    $dirs = Get-ChildItem -Path $OutputPath -Recurse -Directory | Select-Object -ExpandProperty Name -Unique

    # Get log types in use
    $logtypes = Get-ChildItem -Path $OutputPath -Recurse -File | 
        Where-Object {$_.Name -notlike '*merged_fortigate_logs*' } |
        Group-Object { $_.Directory.Name }

    # Create README content header
    Add-Content -Path $readmepath -Value "Fortigate Logs Processing Summary"
    Add-Content -Path $readmepath -Value "Generated: $(Get-Date)"
    Add-Content -Path $readmepath -Value "----------------------------------------`n"
    Add-Content -Path $readmepath -Value "The log types detailed below were discovered during processing."
    Add-Content -Path $readmepath -Value "Reference: https://docs.fortinet.com/document/fortigate/8.0.0/fortios-log-message-reference/160372/list-of-log-types-and-subtypes`n"

    # Define log type descriptions
    foreach ($dir in $dirs) {
        switch ($dir) {
            'EventLogs' {
                $eventCount = ($logtypes | Where-Object { $_.Name -eq 'EventLogs' }).Count
                Add-Content -Path $readmepath -Value "Event Logs (disk-elog* files):"
                Add-Content -Path $readmepath -Value "  Records system and administrative events, such as downloading a backup copy of the configuration, or daemon activities."
                Add-Content -Path $readmepath -Value "  Files: $eventcount`n"
            }

            'AnomalyLogs' {
                $eventCount = ($logtypes | Where-Object { $_.Name -eq 'AnomalyLogs' }).Count
                Add-Content -Path $readmepath -Value "Anomaly Logs (disk-olog* files):"
                Add-Content -Path $readmepath -Value "  Records intrusion attempts."
                Add-Content -Path $readmepath -Value "  Files: $eventcount`n"
            }

            'IPSLogs' {
                $eventCount = ($logtypes | Where-Object { $_.Name -eq 'IPSLogs' }).Count
                Add-Content -Path $readmepath -Value "IPS Logs (disk-plog* files):"
                Add-Content -Path $readmepath -Value "  Records intrusion prevention events."
                Add-Content -Path $readmepath -Value "  Files: $eventcount`n"
            }

            'RiskLogs' {
                $eventCount = ($logtypes | Where-Object { $_.Name -eq 'RiskLogs' }).Count
                Add-Content -Path $readmepath -Value "Risk Logs (disk-rlog* files):"
                Add-Content -Path $readmepath -Value "  Records intrusion attempts."
                Add-Content -Path $readmepath -Value "  Application control log is output when a signature matches an application pattern."
                Add-Content -Path $readmepath -Value "  Files: $eventcount`n"
            }

            'SSLLogs' {
                $eventCount = ($logtypes | Where-Object { $_.Name -eq 'SSLLogs' }).Count
                Add-Content -Path $readmepath -Value "SSL Logs (disk-ssllog* files):"
                Add-Content -Path $readmepath -Value "  Records detected/blocked malicious SSL connections."
                Add-Content -Path $readmepath -Value "  Files: $eventcount`n"
            }

            'TrafficLogs' {
                $eventCount = ($logtypes | Where-Object { $_.Name -eq 'TrafficLogs' }).Count
                Add-Content -Path $readmepath -Value "Traffic Logs (disk-tlog* files):"
                Add-Content -Path $readmepath -Value "  Records traffic flow information, such as an HTTP/HTTPS request and its response, if any."
                Add-Content -Path $readmepath -Value "  Files: $eventcount`n"
            }

            'WebLogs' {
                $eventCount = ($logtypes | Where-Object { $_.Name -eq 'WebLogs' }).Count
                Add-Content -Path $readmepath -Value "Web Logs (disk-wlog* files):"
                Add-Content -Path $readmepath -Value "  Records web filter events."
                Add-Content -Path $readmepath -Value "  Files: $eventcount`n"
            }

            'UnidentifiedLogs' {
                $eventCount = ($logtypes | Where-Object { $_.Name -eq 'UnidentifiedLogs' }).Count
                Add-Content -Path $readmepath -Value "Unidentified Logs:"
                Add-Content -Path $readmepath -Value "  These logs could not be identified by the rules of this script."
                Add-Content -Path $readmepath -Value "  Please refer to Fortigate documentation to identify these logs."
                Add-Content -Path $readmepath -Value "  Files: $eventcount`n"
            }
        }
    }

    return [PSCustomObject]@{
        ReadmePath = $readmepath
    }
}

###################################
# Main
###################################
# Check for .jar file
if (-not (Test-Path $jar)) {
    Write-Host "`n  [ERROR] JAR file not found: $jar. Cannot continue without log_reader.jar. Script exiting."-ForegroundColor Red
    exit
}

# Check for JRE
if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    Write-Host "`n  [ERROR] Java runtime not found in PATH.Cannot continue without Java runtime. Script exiting." -ForegroundColor Red
    exit
}

# Suitability check
$suitabilitywarning = @"

IMPORTANT PRE-PROCESSING CHECK

This script should ONLY be run against RAW log files extracted from Fortigate appliances in their proprietary compressed format.

Compressed archives are NOT supported - please ensure all log files have been extracted from compressed directories before continuing.

"@

Write-Warning $suitabilitywarning
Write-Host "`nDo you want to continue? (y/n): " -ForegroundColor Cyan -NoNewline
$confirmation = Read-Host
if ($confirmation -ne 'y') {
    Write-Host "Script exiting following user pre-processing validation check."
    exit
}

# Start main program
try {

    # Start logging
    $script:LogWriter = [System.IO.StreamWriter]::new($logfilepath, $true)
    
    # Record analyst info
    Write-Log -Level INFO -Message "Processing completed by analyst: $analyst"

    # Display intro banner
    $introtext = @"

This script must be run as administrator.
Folder containing logs must contain the string "fortigate" (case-insensitive).
"@

    Write-Information -MessageData "`nThis script extracts data held in compressed Fortigate device logs.`n" -InformationAction Continue
    Write-Warning -Message $introtext

    # Set config for processing
    $config = Set-ProcessingConfiguration -BaseDirectory $basedirectory

    # Output folder validation
    $fortigateanalysis = Join-Path $config.OutputPath 'FortigateLogs'
    Ensure-Directory -Path $fortigateanalysis | Out-Null

    # Process raw log files
    foreach ($target in $config.Hostnames) {
        Invoke-HostProcessing `
            -Target $target `
            -Jar $jar `
            -OutputRoot $fortigateanalysis `
            -LogDirs $logdirs `
            -ExcludedDirectories $excludeddirs 
        
        # Produce README file for extracted log descriptions
        $hostoutputpath = Join-Path $fortigateanalysis $target.Host
        $readmepath = Make-Readme -OutputPath $hostoutputpath
    }

# Move log file from temporary location to Analysis\Processing Logs folder
} finally {
    Write-Log -Level INFO -Message "Run summary:"
    Write-Log -Level INFO -Message "   Total hosts processed: $($config.Hostnames.Count)"
    Write-Log -Level INFO -Message "   Output directory: $fortigateanalysis"
    Write-Log -Level INFO -Message "   Analyst: $analyst"
    Write-Log -Level SUCCESS -Message "Log processing complete. Script exiting."
    $script:LogWriter.Close()
    if ($config -and $config.OutputPath) {
        $logdir = Join-Path $config.OutputPath 'Processing Logs'
        Move-Item -LiteralPath $logfilepath -Destination $logdir -Force
        Write-Host "`n  [INFO] Log file saved at: $($config.OutputPath)$($logfile)." -ForegroundColor White
        Write-Host "`n  [INFO] Details of extracted logs can be found in the README saved at: $($readmepath.ReadmePath).`n" -ForegroundColor White
    } else {
        Remove-Item -LiteralPath $logfilepath
    }
}
