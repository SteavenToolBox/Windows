Set-ExecutionPolicy Unrestricted -scope CurrentUser
# Get all logical disks
$logicalDisks = Get-WmiObject -Query "SELECT * FROM Win32_LogicalDisk"

# Loop through each logical disk and get the associated physical disk model
foreach ($logicalDisk in $logicalDisks) {
    $partition = Get-WmiObject -Query "ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='$($logicalDisk.DeviceID)'} WHERE AssocClass=Win32_LogicalDiskToPartition"
    if ($partition) {
        $disk = Get-WmiObject -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$($partition.DeviceID)'} WHERE AssocClass=Win32_DiskDriveToDiskPartition"
        if ($disk) {
            # Skip if the disk model matches Red Hat VirtIO SCSI Disk Device
            if ($disk.Model -ne "Red Hat VirtIO SCSI Disk Device" -and $disk.MediaType -ne "SSD") {
                $driveLetter = $logicalDisk.DeviceID
                Write-Output "Running maintenance on drive $driveLetter"
                
                # Run chkdsk and defrag commands
                chkdsk "$driveLetter" /f
                defrag "$driveLetter`\" /L
                defrag "$driveLetter`\" /O
            } else {
                Write-Output "Skipping drive $($logicalDisk.DeviceID) - Disk model: $($disk.Model)"
            }
        }
    }
}