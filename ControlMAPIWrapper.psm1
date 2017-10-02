Function Set-SSLTrustAllCertsPolicy
{
    <#
    .SYNOPSIS
    Bypass unsecured connection error when trying to connect to a server with unimplemented SSL/TLS 
    
    .DESCRIPTION
    Call once in a session before trying to communicate with via http with SSL/TLS by calling commands like Invoke-WebRequest, Invoke-RestMethod
    
    .NOTES
    Source: google search
    #>
    [CmdletBinding()]
    param()
    add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

Function ConvertTo-FormDataBody
{
    <#
    .SYNOPSIS
    Create a Body for Content Type 'Form-Data' message
    
    .DESCRIPTION
    Create a Body for Content Type 'Form-Data' message.
    Returns a hash table with keys ContentType and Body that can be used as input to Invoke-WebRequest or Invoke-RestMethod (usually with -Method Post)
    
    .PARAMETER Content
    Content that will be embedded in the message body in JSON or XML format
    
    .PARAMETER FileName
    A name that will be implemented in the body as if a real file was created and sent.
    it has no effect on the output -just need to be present-.
    default value is 'content.json'
    
    .EXAMPLE
    $BodyAndContentType = Create-FormDataBody $jsonContent
    Invoke-RestMethod -Uri $UriAddress -Method Post -Headers $Headers @BodyAndContentType
    or
    Invoke-RestMethod -Uri $UriAddress -Method Post -Headers $Headers -ContentType $BodyAndContentType.ContentType -Body $BodyAndContentType.Body
    
    .NOTES
    Ref: https://github.com/controlm/automation-api-quickstart/blob/master/201-call-rest-api-using-powershell/AutomationAPIExample.ps1
    #>
    [CmdletBinding()]
    [OutputType([HashTable])]
    param(
    [Parameter(Mandatory=$true,Position=0,ParameterSetName='FromFile')]
    [ValidateScript({Test-Path $_ -PathType Leaf})]
    [string]$Path,
    [Parameter(Mandatory=$true,Position=0,ParameterSetName='Direct')]
    [string]$Content,
    [Parameter(Mandatory=$true,Position=1,ParameterSetName='Direct')]
    [ValidateNotNullOrEmpty()]
    [string]$FileName = 'content.json')
    
    if($PsCmdlet.ParameterSetName -eq 'FromFile')
    {
        $FileName = Split-Path -Path $Path -Leaf
        $fileBin  = [System.IO.File]::ReadAllBytes($Path)
        $enc      = [System.Text.Encoding]::GetEncoding("iso-8859-1")  #($CODEPAGE), Can replace with ASCII or UTF-8
        $Content  = $enc.GetString($fileBin)
    }

    $boundary = [System.Guid]::NewGuid().ToString()
    $LF = "`r`n"
    @{
        Body = (
            "--$boundary",
            "Content-Disposition: form-data; name=`"definitionsFile`"; filename=`"$FileName`"",
		    "Content-Type: application/octet-stream$LF",
            $Content,
            "--$boundary--$LF"
         ) -join $LF
         ContentType = "multipart/form-data; boundary=`"$boundary`""
    }
}

Function Connect-ControlM
{
    <#
    .SYNOPSIS
    Connect to ControlM server
    
    .DESCRIPTION
    Wrapper for /login from Control-M REST API
    Must run this cmdlet before trying to access the server using other commands from this module.
    Creates global read-only connection variable.
    Other functions in this module depend on this connection variable.
    
    .PARAMETER ComputerName
    Control-M EM (Enterprise Manager) Server
    
    .PARAMETER UserName
    UserName for Control-M
    
    .PARAMETER Password
    Password of Control-M user in clear text.
    
    .PARAMETER ByPassSSL
    If active, Bypass unimplemented SSL errors. 
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$UserName,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Password,
        [switch]$BypassSSL)

    Write-Verbose "Connecting to the Control-M Server"

    if($ByPassSSL)
    {
        Set-SSLTrustAllCertsPolicy # Bypass faulty/missing/selfsigned SSL warning
    }

    $CTMEndpoint = "https://$ComputerName`:8443/automation-api"
    
    # Login
    $loginRequest = @{
        Body = ConvertTo-Json -InputObject (@{
                username = $UserName
                password = $Password
            })
        ContentType = 'application/json'
        Method  = 'Post'
    }

    Invoke-RestMethod @loginRequest -Uri "$CTMEndpoint/session/login" -OutVariable login
    if(-not $login)
    {
        throw "Unable to login to Control-M server"
    }

    $VariableResult = @{
        Name   = 'CTMConnection'
        Value  = New-Object -TypeName 'PSCustomObject' -Property (@{
            Endpoint = $CTMEndpoint
            Headers = @{ Authorization = ('Bearer {0}' -f $login.token) }
        })
        Scope  = 'Global'
        Option = 'ReadOnly'
        Description = 'http request header for ControlM connection'
    }
    
    if($Global:CTMConnection -ne $null)
    {
        Remove-Variable -Name 'CTMConnection' -Scope 'Global' -Force
    }

    New-Variable @VariableResult -Verbose
}

function Test-ControlMJobDeployment
{
    <#
    .SYNOPSIS
    Test the job build definition against Control-m server.
    
    .DESCRIPTION
    Wrapper for '/buld' in Control-M REST API
    
    .PARAMETER Definition
    A JSON structured and contains parameters as specified in the Control-M documentation for job definition.  
    
    .PARAMETER JobName
    or document name to include in the request,
    it will return in the response, so its for follow-up when sending several requests together.

    .NOTES
    Useful to check if schedules and timings are valid.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ParameterSetName = 'FromFile')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$Path,
        [Parameter(Mandatory=$true,ParameterSetName = 'Direct')]
        [ValidateNotNullOrEmpty()]
        [string]$Definition,
        [Parameter(Mandatory=$true,ParameterSetName = 'Direct')]        
        [ValidateNotNullOrEmpty()]
        [String]$JobName = 'sample'
    )
    
    if($Global:CTMConnection -eq $null)
    {
        throw 'There is no active Control-M connection. Use Connect-ControlM cmdlet to connect to a Control-M server.'
    }

    Write-Verbose 'Testing job definition against Control-M Server'
    
    $FormDataBody = switch($PsCmdlet.ParameterSetName)
    {
        'Direct'   {ConvertTo-FormDataBody -Content $Definition -FileName "Job-$JobName.json"} # returns a hash table
        'FromFile' {ConvertTo-FormDataBody -Path $Path} # returns a hash table        
    }

    $RequestParams = $FormDataBody + @{
        Headers = $Global:CTMConnection.Headers
        Method  = 'Post'
        Uri = '{0}/build' -f $Global:CTMConnection.Endpoint
        OutVariable = 'Result'
        ErrorAction = 'Stop'
    }

    Invoke-RestMethod @RequestParams
    if($Result)
    {
        $Result | Out-String | Write-Verbose
    }
}

function Push-ControlMJobDeployment
{
    <#
    .SYNOPSIS
    Push a job definition to ControlM Server
    
    .DESCRIPTION
    Wrapper for '/deploy' in Control-M REST API 
    
    .PARAMETER Path
    A path to a file to upload, supported types like: json, zip, jar...

    .PARAMETER Definition
    A JSON structured and contains parameters as specified in the Control-M documentation for job definition.  
    
    .PARAMETER JobName
    or document name to include in the request,
    it will return in the response, so its for follow-up when sending several requests together. 
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ParameterSetName = 'FromFile')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$Path,
        [Parameter(Mandatory=$true,ParameterSetName = 'Direct')]
        [ValidateNotNullOrEmpty()]
        [string]$Definition,
        [Parameter(Mandatory=$true,ParameterSetName = 'Direct')]        
        [ValidateNotNullOrEmpty()]
        [String]$JobName = 'sample'
    )

    if($Global:CTMConnection -eq $null)
    {
        throw 'There is no active Control-M connection. Use Connect-ControlM cmdlet to connect to a Control-M server.'
    }

    Write-Verbose 'Deploying job definitions to Control-M Server'

    $FormDataBody = switch($PsCmdlet.ParameterSetName)
    {
        'Direct'   {ConvertTo-FormDataBody -Content $Definition -FileName "Job-$JobName.json"} # returns a hash table
        'FromFile' {ConvertTo-FormDataBody -Path $Path} # returns a hash table        
    }
    
    $RequestParams = $FormDataBody + @{
        Headers = $Global:CTMConnection.Headers
        Method  = 'Post'
        Uri = '{0}/deploy' -f $Global:CTMConnection.Endpoint
        OutVariable = 'Result'
        ErrorAction = 'Stop'
    }

    Invoke-RestMethod @RequestParams
    if($Result)
    {
        $Result | Out-String | Write-Verbose
    }
}

function Assert-ControlMFolderOrder
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Server,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]        
        [ValidateNotNullOrEmpty()]
        [String]$FolderName
    )

    Begin
    {
        if($Global:CTMConnection -eq $null)
        {
            throw 'There is no active Control-M connection. Use Connect-ControlM cmdlet to connect to a Control-M server.'
        }
    }

    Process {
        Write-Verbose "Ordering all jobs in folder `"$FolderName`" in Control-M Server `"$Server`""

        $RequestParams = @{
            Headers = $Global:CTMConnection.Headers + @{Accept = "application/json"}
            Method  = 'Post'
            Uri = '{0}/run/order' -f $Global:CTMConnection.Endpoint
            Body = ConvertTo-Json -Compress -Depth 100 -InputObject @{ ctm = $Server; folder = $FolderName }
            ContentType = 'application/json'
            OutVariable = 'Result'
            ErrorAction = 'Stop'
        }
        
        Invoke-RestMethod @RequestParams
        if($Result)
        {
            $Result | Out-String | Write-Verbose
        }
    }
}

Function Lock-ControlMJob
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]        
        [ValidateNotNullOrEmpty()]
        [string]$JobId
    )

    Begin
    {
        if($Global:CTMConnection -eq $null)
        {
            throw 'There is no active Control-M connection. Use Connect-ControlM cmdlet to connect to a Control-M server.'
        }
    }

    Process {
        Write-Verbose ''

        $RequestParams = @{
            Headers = $Global:CTMConnection.Headers + @{Accept = "application/json"}
            Method  = 'Post'
            Uri = '{0}/run/job/{1}/hold' -f $Global:CTMConnection.Endpoint, $JobId
            #Body = ConvertTo-Json -Compress -Depth 100 -InputObject @{ ctm = $Server; folder = $FolderName }
            ContentType = 'application/json'
            OutVariable = 'Result'
            ErrorAction = 'Stop'
        }
        
        if ($pscmdlet.ShouldProcess($JobId)){
            Invoke-RestMethod @RequestParams

            if($Result)
            {
                $Result | Out-String | Write-Verbose
            }
        }
    }

}

Function Unlock-ControlMJob
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]        
        [ValidateNotNullOrEmpty()]
        [string]$JobId
    )

    Begin
    {
        if($Global:CTMConnection -eq $null)
        {
            throw 'There is no active Control-M connection. Use Connect-ControlM cmdlet to connect to a Control-M server.'
        }
    }

    Process {
        $RequestParams = @{
            Headers = $Global:CTMConnection.Headers + @{Accept = "application/json"}
            Method  = 'Post'
            Uri = '{0}/run/job/{1}/free' -f $Global:CTMConnection.Endpoint, $JobId
            #Body = ConvertTo-Json -Compress -Depth 100 -InputObject @{ ctm = $Server; folder = $FolderName }
            ContentType = 'application/json'
            OutVariable = 'Result'
            ErrorAction = 'Stop'
        }
        
        if ($pscmdlet.ShouldProcess($JobId)){
            Invoke-RestMethod @RequestParams

            if($Result)
            {
                $Result | Out-String | Write-Verbose
            }
        }
    }

}

Function Undo-ControlMJobRemoval
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]        
        [ValidateNotNullOrEmpty()]
        [string]$JobId
    )

    Begin
    {
        if($Global:CTMConnection -eq $null)
        {
            throw 'There is no active Control-M connection. Use Connect-ControlM cmdlet to connect to a Control-M server.'
        }
    }

    Process {
        $RequestParams = @{
            Headers = $Global:CTMConnection.Headers + @{Accept = "application/json"}
            Method  = 'Post'
            Uri = '{0}/run/job/{1}/undelete' -f $Global:CTMConnection.Endpoint, $JobId
            ContentType = 'application/json'
            OutVariable = 'Result'
            ErrorAction = 'Stop'
        }
        
        if ($pscmdlet.ShouldProcess($JobId)){
            Invoke-RestMethod @RequestParams

            if($Result)
            {
                $Result | Out-String | Write-Verbose
            }
        }
    }

}

Function Get-ControlMJobStatus
{
    <#
    .SYNOPSIS
    Short description

    .DESCRIPTION
    Parameter set name 'specific' overrides:
    GET /run/job/{jobId}/status
    Get the job status.

    Parameter set name 'filtered' overrides:
    GET /run/jobs/status
    Get status of jobs that match the requested search criteria.

    .PARAMETER Limit
    maximum jobs status to fetch (default 1000).

    .PARAMETER JobName
    Parameter description

    .PARAMETER Ctm
    Parameter description

    .PARAMETER Application
    Parameter description

    .PARAMETER SubApplication
    Parameter description

    .PARAMETER HostName
    Parameter description

    .PARAMETER Status
    Parameter description

    .PARAMETER Folder
    Parameter description

    .PARAMETER Description
    Parameter description

    .PARAMETER JobId
    Parameter description

    .EXAMPLE
    An example

    .NOTES
    #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(ParameterSetName='filtered')]
        [long]$limit,
        [Parameter(ParameterSetName='filtered')]
        [string]$jobname,
        [Parameter(ParameterSetName='filtered')]
        [string]$ctm,
        [Parameter(ParameterSetName='filtered')]
        [string]$application,
        [Parameter(ParameterSetName='filtered')]
        [string]$subApplication,
        [Parameter(ParameterSetName='filtered')]
        [string]$HostName, # 'host' in REST API
        [Parameter(ParameterSetName='filtered')]
        [string]$status,
        [Parameter(ParameterSetName='filtered')]
        [string]$folder,
        [Parameter(ParameterSetName='filtered')]
        [string]$description,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ParameterSetName='specific')]        
        [ValidateNotNullOrEmpty()]
        [string]$JobId
    )

    Begin
    {
        if($Global:CTMConnection -eq $null)
        {
            throw 'There is no active Control-M connection. Use Connect-ControlM cmdlet to connect to a Control-M server.'
        }
    }
    
    Process {

        $RequestParams = @{
            Headers = $Global:CTMConnection.Headers + @{Accept = "application/json"}
            Method  = 'Get'
            ContentType = 'application/json'
            OutVariable = 'Result'
            ErrorAction = 'Stop'
        }

        switch ($PsCmdlet.ParameterSetName)
        {
            'specific' {
                $RequestParams.Add('Uri',('{0}/run/job/{1}/status' -f $Global:CTMConnection.Endpoint, $JobId))
            }
            'filtered' {
                $filter = ($PSBoundParameters.Keys | Where-Object{-not [string]::IsNullOrWhiteSpace($PSBoundParameters[$_]) -and 
                    [System.Management.Automation.PSCmdlet]::CommonParameters -notcontains $_ -and
                    [System.Management.Automation.PSCmdlet]::OptionalCommonParameters -notcontains $_ } | ForEach-Object{
                    if($_ -eq 'HostName'){
                        "{0}={1}" -f 'host', $PSBoundParameters[$_]                        
                    }
                    else{
                        "{0}={1}" -f $_.trim(), $PSBoundParameters[$_]
                    }
                }) -join '&'

                $RequestParams.Add('Uri',(('{0}/run/jobs/status' -f $Global:CTMConnection.Endpoint) ,$filter -join '?'))
            }
        }
        
        if ($pscmdlet.ShouldProcess($RequestParams.Uri)){
            Invoke-RestMethod @RequestParams

            if($Result)
            {
                $Result | Out-String | Write-Verbose
            }
        }
    }
}

Function Stop-ControlMJob
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]        
        [ValidateNotNullOrEmpty()]
        [string]$JobId
    )

    Begin
    {
        if($Global:CTMConnection -eq $null)
        {
            throw 'There is no active Control-M connection. Use Connect-ControlM cmdlet to connect to a Control-M server.'
        }
    }

    Process {
        $RequestParams = @{
            Headers = $Global:CTMConnection.Headers + @{Accept = "application/json"}
            Method  = 'Post'
            Uri = '{0}/run/job/{1}/kill' -f $Global:CTMConnection.Endpoint, $JobId
            ContentType = 'application/json'
            OutVariable = 'Result'
            ErrorAction = 'Stop'
        }

        if ($pscmdlet.ShouldProcess($JobId)){
            Invoke-RestMethod @RequestParams

            if($Result)
            {
                $Result | Out-String | Write-Verbose
            }
        }
    }
}

Function Remove-ControlMJob
{
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]        
        [ValidateNotNullOrEmpty()]
        [string]$JobId
    )

    Begin
    {
        if($Global:CTMConnection -eq $null)
        {
            throw 'There is no active Control-M connection. Use Connect-ControlM cmdlet to connect to a Control-M server.'
        }
    }

    Process {
        $RequestParams = @{
            Headers = $Global:CTMConnection.Headers + @{Accept = "application/json"}
            Method  = 'Post'
            Uri = '{0}/run/job/{1}/delete' -f $Global:CTMConnection.Endpoint, $JobId
            ContentType = 'application/json'
            OutVariable = 'Result'
            ErrorAction = 'Stop'
        }

        if ($pscmdlet.ShouldProcess($JobId)){
            Invoke-RestMethod @RequestParams

            if($Result)
            {
                $Result | Out-String | Write-Verbose
            }
        }
    }
}

function Disconnect-ControlM
{
    <#
    .SYNOPSIS
    Disconnect ControlM Server
    
    .DESCRIPTION
    Invoke logout post request with token to ControlM to end session.
    Remove the $CTMConnection global variable.
    #>
    [Cmdletbinding()]
    param()
    
    Write-Verbose "Disconnecting from the Control-M Server"
    
    Invoke-RestMethod -Uri "$($CTMConnection.Endpoint)/session/logout" -Method Post -Headers $CTMConnection.Headers -OutVariable logout
    if($logout)
    {
        Write-Verbose $logout.message
    }

    if($Global:CTMConnection -ne $null)
    {
        Remove-Variable -Name 'CTMConnection' -Scope 'Global' -Force
    }
}

New-Alias -Name 'Login-ControlM'       -Value 'Connect-ControlM'
New-Alias -Name 'Logout-ControlM'      -Value 'Disconnect-ControlM'
New-Alias -Name 'Build-ControlMJob'    -Value 'Test-ControlMJobDeployment'
New-Alias -Name 'Deploy-ControlMJob'   -Value 'Push-ControlMJobDeployment'
New-Alias -Name 'Order-ControlMFolder' -Value 'Assert-ControlMFolderOrder'
New-Alias -Name 'Kill-ControlMJob'     -Value 'Stop-ControlMJob'
New-Alias -Name 'Hold-ControlMJob'     -Value 'Lock-ControlMJob'
New-Alias -Name 'Free-ControlMJob'     -Value 'Unlock-ControlMJob'
New-Alias -Name 'Delete-ControlMJob'   -Value 'Remove-ControlMJob'
New-Alias -Name 'Undelete-ControlMJob' -Value 'Undo-ControlMJobRemoval'

$ExportParams = @{
    Function = @(
        'Connect-ControlM'
        ,'Disconnect-ControlM'
        ,'Test-ControlMJobDeployment'
        ,'Push-ControlMJobDeployment'
        ,'Assert-ControlMFolderOrder'
        ,'Stop-ControlMJob'
        ,'Lock-ControlMJob'
        ,'Unlock-ControlMJob'
        ,'Remove-ControlMJob'
        ,'Undo-ControlMJobRemoval'
        ,'Get-ControlMJobStatus'
    )
    Alias = @(
        'Login-ControlM'      
        ,'Logout-ControlM'     
        ,'Build-ControlMJob'   
        ,'Deploy-ControlMJob'  
        ,'Order-ControlMFolder'
        ,'Kill-ControlMJob'    
        ,'Hold-ControlMJob'    
        ,'Free-ControlMJob'    
        ,'Delete-ControlMJob'  
        ,'Undelete-ControlMJob'
    )
}

Export-ModuleMember @ExportParams