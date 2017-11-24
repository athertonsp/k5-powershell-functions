# Import K5 json definitions function
. $PSScriptRoot/k5json.ps1

# Only TLS 1.2 allowed, Powershell needs to be forced as it won't negotiate!
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#Main Functions below written by Pete Beverley 6 July 2017

Function Get-K5Token
{
    <#

    .SYNOPSIS
    Retrieves a token from the K5 identity service (keystone) to provide authentication for subsequent calls to K5 API endpoints

    .DESCRIPTION
    The Get-K5Token function retrieves a token from the K5 identity service scoped as requested using supplied credentials. The token
    should be saved in a variable and used to authenticate subsequent calls to K5 API endpoints. If called without parameters the region
    will default to uk-1 and contract, username, password, and project will be retrieved from k5env.csv which must exist in the same
    location as the script containing this function and be formatted as follows (OpenSSLPath only required if you intend to use the
    Get-K5WindowsPassword function to decrypt the k5user password assigned during the build process, thumbprint only required if your
    user is configured for two factor auth):

    "name","value"
    "k5user","username"
    "k5pword","password"
    "k5project","projectname"
    "proxyURL","http://your.proxy.name"
    "k5_uk_contract","uk_contract"
    "k5_de_contract","de_contract"
    "k5_fi_contract","fi_contract"
    "OpenSSLPath","C:\your\path\to\openssl.exe"
    "thumbprint","ClientCertThumbprint"

    The object returned by the Get-K5Token function has a number of properties:
    
    domainid    The id of the domain (contract) to which the token is scoped
    endpoints   A hashtable containing all the applicable API endpoints for the token's scope 
    expiry      A timestamp indicating when the token will expire
    projectid   The id of the project to which the token is scoped
    projects    An object containing details of all projects to which the user has access
    token       A hashtable containing the returned authentication token
    userid      The id of the user to whom the token has been issued

    .PARAMETER region
    The region to scope to, defaults to uk-1

    .PARAMETER contract
    The contract to scope to, defaults to the contract specified in k5env.csv for the region to which you are scoping.

    .PARAMETER user
    Your K5 username for the specified contract, defaults to the username stored in k5env.csv

    .PARAMETER password
    The password for the specified K5 username, defaults to the password stored in k5env.csv

    .PARAMETER projectname
    The project within the specified contract to which you wish to scope, defaults to the project specified in k5env.csv

    .PARAMETER global
    Switch parameter to specify the token should be globally scoped

    .PARAMETER unscoped
    Switch parameter to specify the token should not be scoped to a project

    .PARAMETER useProxy
    Switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used

    .EXAMPLE

    # Retrieve a token using the defaults stored in k5env.csv and store in $token for future use

PS C:\>$token = Get-K5Token

    .EXAMPLE

    # Retrieve a token supplying all required authentication information and store in $token for future use, use the proxy when making the call

PS C:\>$token = Get-K5Token -region de-1 -contract mycontract -user myuser -password mypassword -projectname myproject -useProxy

    .EXAMPLE

    # Show the returned token's expiry

PS C:\>$token.expiry

05 April 2017 16:20:23


    #>
    [cmdletbinding(DefaultParameterSetName=’Scoped’)]
    param
    (
        # Region parameter - default to uk-1
        [Parameter()][ValidateSet('de-1','fi-1','uk-1','es-1','jp-east-1')][string]$region = "uk-1",
        # Contract parameter - default to appropriate free tier contract for the specified region
        [string]$contract = $(
                                switch ($region)
                                {
                                    "uk-1" {$((Get-K5Vars)["k5_uk_contract"])}
                                    "fi-1" {$((Get-K5Vars)["k5_fi_contract"])}
                                    "de-1" {$((Get-K5Vars)["k5_de_contract"])}
                                    "es-1" {$((Get-K5Vars)["k5_es_contract"])}
                                }
                            ),
        # User parameter - default to required user
        [string]$user = $((Get-K5Vars)["k5user"]),
        # Password parameter - default to required user's password
        [string]$password = $((Get-K5Vars)["k5pword"]),
        # Project name parameter - default to required project
        [Parameter(ParameterSetName="Scoped")][string]$projectname = $((Get-K5Vars)["k5project"]),
        # Global token scope parameter - default to false
        [Parameter(ParameterSetName="Global")][switch]$global = $false,
        # Unscoped token parameter - default to false
        [Parameter(ParameterSetName="Unscoped")][switch]$unscoped = $false,
        # Use proxy switch parameter
        [switch]$useProxy
    )

    # URL for the specified region's identity service, future calls will use the endpoint returned when retrieving the token
    $regional_identity_url = "https://identity.$region.cloud.global.fujitsu.com/v3/auth/tokens"
    # Global identity service URL
    $global_identity_url = "https://auth-api.jp-east-1.paas.cloud.global.fujitsu.com/API/paas/auth/token"
    # Default header for REST API calls, accept JSON returns
    $headers = @{"Accept" = "application/json"}
    # Define the token object for the function return
    $token = "" | select "token","region","projectid","userid","domainid","expiry","endpoints","projects"
    $token.region = $region

    # Check if we need to return a globally scoped token
    if ($global)
    {
        try
        {
            # Retrieve the JSON for a global token request
            $json = get-k5json token_global
            # Make the API call to request a token from the global identity endpoint
            $detail = Invoke-WebRequest2 -Uri "$global_identity_url" -Method POST -headers $headers -Body $json -ContentType "application/json" -UseProxy $useProxy
            # Extract the payload from the API return and convert from JSON to a PS object
            $return = $detail.Content | ConvertFrom-json
            # Set the token property stored in the headers of the API return
            $token.token = @{"Token" = $detail.headers["X-Access-Token"]}
            # Set the token expiry time
            $token.expiry = [DateTime]([xml.xmlconvert]::ToDateTime($return.token.expires_at)).DateTime
        }
        catch
        {
            # If something went wrong, display an error and exit
            Display-Error -error "Global token retrieval failed..." -errorObj $_
        }
        # Exit and return the token object
        return $token
    }
    
    # Retrieve unscoped token   
    try
    {
        # Retrieve the JSON for an unscoped token request
        $json = get-k5json token_unscoped
        # Make the API call to request a token from the regional identity endpoint
        $detail = Invoke-WebRequest2 -Uri "$regional_identity_url" -Method POST -headers $headers -Body $json -ContentType "application/json" -UseProxy $useProxy
        # Extract the payload from the API return and convert from JSON to a PS object
        $return = $detail.Content | ConvertFrom-json
    }
    catch
    {
        # If something went wrong, display an error and exit
        Display-Error -error "Unscoped token retrieval failed..." -errorObj $_
    }
    # Set the token property stored in the headers of the API return
    $token.token = @{"X-Auth-Token" = $detail.headers["X-Subject-Token"]}
    # Set the domain id property
    $token.domainid = $return.token.project.domain.id
    # Set the user id property
    $token.userid = $return.token.user.id
    # Set the project id property
    $token.projectid = $return.token.project.id
    # Retrieve the endpoints from the API return and set the endpoints property accordingly
    $token.endpoints = Process-Endpoints $return.token.catalog.endpoints
    # Set the token expiry property
    $token.expiry = [DateTime]([xml.xmlconvert]::ToDateTime($return.token.expires_at)).DateTime
    # Add the token to the headers object for authenticating the following API calls 
    $headers += $token.token
    # Enumerate the projects available to this user
    try
    {
        # Make the API call to retrieve the list of projects accessible to this user from the identity endpoint
        $detail = Invoke-WebRequest2 -Uri "$($token.endpoints["identityv3"])/users/$($token.userid)/projects" -Method GET -headers $headers -ContentType "application/json" -UseProxy $useProxy
        # Extract the payload from the API return and convert from JSON to a PS object
        $return = $detail.Content | ConvertFrom-Json
    }
    catch
    {
        # If something went wrong, display an error and exit
        Display-Error -error "Project enumeration failed..." -errorObj $_
    }
    # Set the projects property using the projects returned from the API call        
    $token.projects = $return.projects
    # Do we require a scoped token?
    if (-not $unscoped)
    {
        # Scoped token required, find the project id of the project we need to scope to
        $token.projectid = ($return.projects | where name -eq $projectname).id
        # If we can't find a project id for the specified project name display an error and exit
        if ( -not $token.projectid) { Display-Error -error "Project $projectname not found."}
        # Reset the headers
        $headers = @{"Accept" = "application/json"}
        try
        {
            # Set the projectid propert expected in the JSON skeleton
            $projectid = $token.projectid
            # Retrieve the JSON for an scoped token request
            $json = get-k5json token_scoped
            # Make the API call to request a token from the identity endpoint
            $detail = Invoke-WebRequest2 -Uri "$($token.endpoints["identityv3"])/auth/tokens" -Method POST -headers $headers -Body $json -ContentType "application/json" -UseProxy $useProxy
            # Extract the payload from the API return and convert from JSON to a PS object
            $return = $detail.Content | ConvertFrom-json
        }
        catch
        {
            # If something went wrong, display an error and exit
            Display-Error -error "Scoped token retrieval failed..." -errorObj $_
        }
        # Scoped token, retrieve the endpoints from the API return and set the endpoints property accordingly
        $token.endpoints = Process-Endpoints $return.token.catalog.endpoints
        # Set the token property
        $token.token = @{"X-Auth-Token" = $detail.headers["X-Subject-Token"]}
        # Set the token expiry property
        $token.expiry = [DateTime]([xml.xmlconvert]::ToDateTime($return.token.expires_at)).DateTime
    }
    # Return the token object
    return $token
    
}

Function Process-Endpoints
{
    param
    (
        [array]$endpointlist
    )
    $endpoints = @{}
    foreach ($endpoint in $endpointlist)
    {
        $endpoints.Add($endpoint.name,$endpoint.url)
    }
    return $endpoints
}

Function Get-K5Vars
{
    $k5vars = @{} 
    $vars = Import-Csv $PSScriptRoot\k5env.csv
    foreach ($var in $vars)
    {
        $k5vars.Add($var.name,$var.value)
    }
    return $k5vars
}

Function Display-Error
{
    param
    (
        [string]$error,
        [pscustomobject]$errorObj
    )
    Write-Host "Error: $error" -ForegroundColor Red
    if ($errorObj)
    {
        Write-Host "Exception: $($errorObj.Exception.Message)" -ForegroundColor Red
        Write-Host "$($errorObj.InvocationInfo.PositionMessage)" -ForegroundColor Red
    }
    break
}

# Mirror Invoke-WebRequest function to allow use (or not) of proxy and certificates within the K5 functions without hardcoding
Function Invoke-WebRequest2
{
    param
    (
        [string]$Uri,
        [string]$Method,
        [hashtable]$Headers,
        [string]$Body,
        [string]$ContentType,
        [pscustomobject]$token,
        #Added by Steve Atherton 19/7/17
        [string]$TransferEncoding,
        [bool]$UseProxy=$false
    )
    # If a token was passed in check it's expiry and inform user if it's expired
    if (($token) -and ($token.expiry -le [datetime]::Now)) {Display-Error "Token has expired, please obtain another..."}
    # Retrieve certificate thumbprint if it's been set
    $thumbprint = $((Get-K5Vars)["thumbprint"])
    # Base comand
    $cmd = 'Invoke-WebRequest -Uri $Uri -Method $Method -headers $Headers -ContentType $ContentType '
    # Add body if required
    if ($Body) {$cmd = $cmd + '-Body $Body '}
    #Add TransferEncoding if required - ADDED 19/7/17 Steve Atherton
    if ($TransferEncoding) {$cmd = $cmd + '-TransferEncoding $TransferEncoding '}
    # Add proxy if required
    if ($UseProxy) {$cmd = $cmd + '-Proxy $((Get-K5Vars)["proxyURL"]) -ProxyUseDefaultCredentials '}
    # Add certificate thumbprint if required
    if ($thumbprint) {$cmd = $cmd + '-CertificateThumbprint $thumbprint '}
    try
    {
        $return = Invoke-Expression $cmd
    }
    catch
    {
        # Check to see if proxy auth failed and user forgot to specify using a proxy...
        if (($_.Exception.Message -match "\(407\) Proxy") -and (-not $useProxy))
        # We need to try the proxy
        {
            $cmd = $cmd + '-Proxy $((Get-K5Vars)["proxyURL"]) -ProxyUseDefaultCredentials '
            $return = Invoke-Expression $cmd
        } else {
            # Something else went wrong, throw the erro back to the caling function
            throw $_
        }
    }
    # Return the web request return
    return $return
}

Function Get-K5UserGroups
{
    param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [switch]$useProxy
    )
    if (-not $token){break}
    try
    {
        $headers = @{"Accept" = "application/json"}
        $headers += $token.token
        $detail = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["identityv3"])/users/?domain_id=$($token.domainid)" -Method GET -headers $headers -ContentType "application/json" -UseProxy $useProxy
        $users = ($detail.Content | ConvertFrom-Json).users
        $usergroups = @()
        foreach ($user in $users)
        {
            $detail = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["identityv3"])/users/$($user.id)/groups" -Method GET -headers $headers -ContentType "application/json" -UseProxy $useProxy
            $return = $detail.Content | ConvertFrom-Json
            foreach ($group in $return.groups)
            {
                $usergroup = "" | select "Username","Group","Description","id"
                $usergroup.Username = $user.name
                $usergroup.Group = $group.name
                $usergroup.Description = $group.description
                $usergroup.id = $group.id
                $usergroups += $usergroup
            }
        }
    }
    catch
    {
        Display-Error -error "Get-K5UserGroups failed..." -errorObj $_
    }
    return $usergroups
}

Function Get-K5Resources
{
    <#

    .SYNOPSIS
    Retrieves a list of K5 resources of a given type

    .DESCRIPTION
    The Get-K5Resources function retrieves a list of resources of a given type, optionally for a specific resource name.
    The list is either comprised of names and ids, or if required, a detailed list of all attributes.

    .PARAMETER token
    Required, a token object returned by the Get-K5Token function

    .PARAMETER type
    Required, the type of resource required, if not specified the error message will detail the acceptable types

    .PARAMETER name
    Optional, the name of the resource required, eg the server name if type is servers

    .PARAMETER detailed
    Optional, switch to request detailed list

    .PARAMETER useProxy
    Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

    .EXAMPLE 
    
# Get a simple list of names and ids of all servers, use proxy when making the call
    
PS C:\>Get-K5Resources -token $token -type servers -UseProxy

name                      id                                  
----                      --                                  
WinTest                   ecff651a-0e4d-4685-8dcc-f1064384f717
meta_test                 486ca902-8ff8-3979-a1c6-db38b7862d3e
ACT_Project_a_Server2_AZ1 843f0b1b-df88-417a-b822-2a689fd9432a
ACT_Project_a_Server1_AZ1 21dd980d-a50a-44cf-b4fc-270a579dc788
ACT_Project_a_Server2_AZ2 90756aa3-5373-4901-b4ea-70ce358f97dd
ACT_Project_a_Server1_AZ2 20f7c1de-5d40-bd67-d173-b813148ca5b4

    .EXAMPLE 
# Get a detailed list of attributes for server named WinTest
    
PS C:\>PSGet-K5Resources -token $token -type servers -name WinTest -detailed


status                               : ACTIVE
updated                              : 2017-04-05T09:27:26Z
hostId                               : f60457d820d0dd319f19a1c2d2a234552a7356d7597756b1ed02e3fb
OS-EXT-SRV-ATTR:host                 : gb1a01-pgy023-00
addresses                            : @{ACT_Project_a_Net_AZ1=System.Object[]}
links                                : {@{href=http://10.19.0.201/v2/3d7a4ca55d2f4ff8b0fd7175d4bdde9f/servers/ecff651a-0e4d-4685-8dcc-f1064384f717; rel=self}, 
                                       @{href=http://10.19.0.201/3d7a4ca55d2f4ff8b0fd7175d4bdde9f/servers/ecff651a-0e4d-4685-8dcc-f1064384f717; rel=bookmark}}
key_name                             : ACT_KP_AZ1
image                                : @{id=6ef614db-1145-42a0-8ec2-bc4d526aa4be; links=System.Object[]}
OS-EXT-STS:task_state                : 
OS-EXT-STS:vm_state                  : active
OS-EXT-SRV-ATTR:instance_name        : instance-00014b43
OS-SRV-USG:launched_at               : 2017-04-05T09:27:25.000000
OS-EXT-SRV-ATTR:hypervisor_hostname  : gb1a01-pgy023-00
flavor                               : @{id=1102; links=System.Object[]}
id                                   : ecf2d41a-0f1d-4a45-8fcc-f1045384f717
security_groups                      : {@{name=default}}
OS-SRV-USG:terminated_at             : 
OS-EXT-AZ:availability_zone          : uk-1a
user_id                              : 9a64f6341e6414d7839f0620422cbdaa
name                                 : WinTest
created                              : 2017-04-05T09:02:11Z
tenant_id                            : 5d7a4cd55e3f6f40b84d717ad4f4de97
OS-DCF:diskConfig                    : MANUAL
os-extended-volumes:volumes_attached : {@{id=05a3d439-5800-46c4-8ade-550b547af25c}}
accessIPv4                           : 
accessIPv6                           : 
progress                             : 0
OS-EXT-STS:power_state               : 1
config_drive                         : 
metadata                             : @{admin_pass=}

    #>

    param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$type = $(Display-Error -error "Please specify a resource type using the -type parameter"),
        [string]$name,
        [switch]$detailed,
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $type)) {break}
    $type_nw    = "routers","networks","subnets","ports","security-groups","security-group-rules","floatingips","network_connectors","network_connector_endpoints"
    $type_fw    = "firewalls","firewall_rules","firewall_policies"
    $type_vpn   = "ipsecpolicies","ipsec-site-connections","vpnservices","ikepolicies"
    $type_comp  = "servers","images","flavors","os-keypairs"
    $type_block = "volumes","types","snapshots"
    $type_obj   = "containers"
    $type_user  = "users","groups"
    $type_role = "roles"
    $type_stack = "stacks"
    $type_db = "instances"
    $type_limit = "limits"
    $validtypes = ((Get-Variable -name type_*).Value | sort) -join ", " 
    switch ($type)
    {
       {$_ -in $type_nw}    {$endpoint = $token.endpoints["networking"] + "/v2.0/" + $type}
       {$_ -in $type_fw}    {$endpoint = $token.endpoints["networking"] + "/v2.0/fw/" + $type}
       {$_ -in $type_vpn}   {$endpoint = $token.endpoints["networking"] + "/v2.0/vpn/" + $type}
       {$_ -in $type_comp}  {$endpoint = $token.endpoints["compute"] +"/" + $type}
       {$_ -in $type_limit} {$endpoint = $token.endpoints["compute"] +"/" + $type}
       {$_ -in $type_block} {$endpoint = $token.endpoints["blockstoragev2"] +"/" + $type}
       {$_ -in $type_obj}   {$endpoint = $token.endpoints["objectstorage"] + "/?format=json"}
       {$_ -in $type_user}  {$endpoint = $token.endpoints["identityv3"] + "/" + $type + "/?domain_id=" + $token.domainid}
       {$_ -in $type_role}  {$endpoint = $token.endpoints["identityv3"] + "/roles"}
       {$_ -in $type_stack} {$endpoint = $token.endpoints["orchestration"] +"/stacks"}
       {$_ -in $type_db}    {$endpoint = $token.endpoints["database"] +"/instances"}
       default              {Display-Error -error "Unknown type `'$type`' - acceptable values are $validtypes"}
    }
    if (-not $endpoint){break}
    try
    {
        if ($type -in $type_limit)
        {
            $return = @()
            $detail = (Invoke-WebRequest2 -token $token -Uri "${endpoint}?availability_zone=$($token.region)a" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy | ConvertFrom-Json).limits.absolute
            $detail | Add-Member -MemberType NoteProperty -Name "AZ" -Value "$($token.region)a"
            $return += $detail
            $detail = (Invoke-WebRequest2 -token $token -Uri "${endpoint}?availability_zone=$($token.region)b" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy | ConvertFrom-Json).limits.absolute
            $detail | Add-Member -MemberType NoteProperty -Name "AZ" -Value "$($token.region)b"
            $return += $detail
            return $return
            break
        }
        $detail = (Invoke-WebRequest2 -token $token -Uri "$endpoint" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy).content | ConvertFrom-Json
        if ($detail)
        {
            if ($type -in $type_obj)
            {
                if ($name) {$detail = $detail  | where name -eq $name}
                if (-not $detail) { Display-Error -error "Resource named: $name of type: $type not found"}
                if ($detailed)
                {
                    $return = @()
                    foreach ($container in $detail)
                    {
                        $detail2 = Invoke-WebRequest2 -token $token -Uri "$($endpoint.replace('/?format=json',''))/$($container.name)?format=json" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy | ConvertFrom-Json
                        foreach ($object in $detail2)
                        {
                            $object | Add-Member -MemberType NoteProperty -Name "Container" -Value $container.name
                            $return += $object
                        }
                        
                    }
                    
                } else {
                    $return = $detail
                }
                return $return
            } else {
                while (($detail | gm -MemberType NoteProperty).count -in 1..2)
                {
                    $detail = $detail.$(($detail | gm | where name -ne "links")[-1].Name)
                }
                if ($detail.stack_name -ne $null){$detail | Add-Member -MemberType AliasProperty -Name name -Value stack_name}
                if ($name)
                {
                    $detail = $detail  | where name -eq $name
                    if (-not $detail) { Display-Error -error "Resource named '$name' of type '$type' not found"}
                }
                if ($detailed)
                {
                    if ((($detail.links -ne $null) -or ($detail.id -eq $null)) -and ( $type -ne $user))
                    {
                        $return = @()
                        if ($detail.links -ne $null){$ids = $detail.id} else {$ids = $detail.name}
                        foreach ($id in $ids)
                        {
                            $return += (Invoke-WebRequest2 -token $token -Uri "$endpoint/$id" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy).content | ConvertFrom-Json
                        }
                        $return = $return.$(($return | gm)[-1].Name)
                    } else {
                        $return = $detail
                    }
                } else {
                    $return = $detail | select name,id
                }
            }
        }
    }
    catch
    {
        Display-Error -error "Get-K5Resources failed..." -errorObj $_
    }
    foreach ($object in $return)
    {
        $object | Add-Member -MemberType NoteProperty -Name "self" -Value "$endpoint/$($object.id)"
    }
    return $return
}


Function Get-K5RoleToGroupAssignments
{
    param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$groupid = $(Display-Error -error "Please specify a group id using the -groupid parameter"),
        [string]$projectid = $($token.projectid),
        [switch]$UseProxy
    )
    $detail = (Invoke-WebRequest2 -Uri "$($token.endpoints["identityv3"])/projects/$projectid/groups/$groupid/roles" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy).Content | ConvertFrom-Json
    return $detail.roles
}

Function Modify-K5RoleToGroupAssignments
{
    param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$roleid = $(Display-Error -error "Please specify a role id using the -roleid parameter"),
        [string]$groupid = $(Display-Error -error "Please specify a group id using the -groupid parameter"),
        [string]$projectid = $($token.projectid),
        [Parameter()][ValidateSet('Add','Delete')][string]$operation = "Add",
        [switch]$UseProxy
    )
    switch ($operation)
    {
        Add    {$detail = (Invoke-WebRequest2 -Uri "$($token.endpoints["identityv3"])/projects/$projectid/groups/$groupid/roles/$roleid" -Method PUT -headers $token.token -ContentType "application/json" -UseProxy $useProxy).Content | ConvertFrom-Json}
        Delete {$detail = (Invoke-WebRequest2 -Uri "$($token.endpoints["identityv3"])/projects/$projectid/groups/$groupid/roles/$roleid" -Method DELETE -headers $token.token -ContentType "application/json" -UseProxy $useProxy).Content | ConvertFrom-Json}
    }
    if ($useProxy)
    {
        Get-K5RoleToGroupAssignments -token $token -groupid $groupid -projectid $projectid -UseProxy
    } else {
        Get-K5RoleToGroupAssignments -token $token -groupid $groupid -projectid $projectid
    }
}


Function Get-K5VNCConsole
{
    <#

    .SYNOPSIS
    Retrieves time limited URL to access the console of a given server

    .DESCRIPTION
    The Get-K5VNCConsole function retrieves a time limited URL which can then be used to access the console of a given server
    via your browser.

    .PARAMETER token
    Required, a token object returned by the Get-K5Token function

    .PARAMETER servername
    Required, the name of the server to establish a console session on

    .PARAMETER useProxy
    Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

    .EXAMPLE 
    
# Retrieve a URL to use for console access to the server named WinTest using proxy when making the call
    
PS C:\>Get-K5VNCConsole -token $token -servername WinTest -UseProxy

https://console-a.uk-1.cloud.global.fujitsu.com/vnc_auto.html?token=f8049b3a-8fd0-4afe-9427-8f4ab765aa29

    #>    param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$servername = $(Display-Error -error "Please specify a server name using the -servername parameter"),
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $servername)) {break}
    try
    {
        $return = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["compute"])/servers" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy
        $serverid = (($return.Content | ConvertFrom-Json).servers | where name -eq $servername).id
        if (-not $serverid)
        {
            Display-Error -error "Get-K5VNCConsole - Server $servername not found."
        }
        $json = Get-K5JSON vnc_console
        $return = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["compute"])/servers/$serverid/action" -Method POST -headers $token.token -Body $json -ContentType "application/json" -UseProxy $useProxy
        $url = ($return.content | ConvertFrom-Json).console.url
    }
    catch
    {
        Display-Error -error "Get-K5VNCConsole failed..." -errorObj $_
    }
    return $url
}

Function Get-K5TTYConsole
{
    <#

    .SYNOPSIS
    Retrieves serial console output of a given server

    .DESCRIPTION
    The Get-K5TTYConsole function retrieves the output of the serial console of a given server, by default it will return the last 50 lines
    but more (or less) can be retrieved by use of the -lines parameter

    .PARAMETER token
    Required, a token object returned by the Get-K5Token function

    .PARAMETER servername
    Required, the name of the server from which to return the console output

    .PARAMETER lines
    Optional, the number of lines of console output to return

    .PARAMETER useProxy
    Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

    .EXAMPLE 
    
# Get the last 5 lines of console output from server named WinTest using proxy when making the call
    
PS C:\>Get-K5TTYConsole -token $token -servername WinTest -UseProxy -lines 5

2017-04-05 09:32:03.999 1408 DEBUG cloudbaseinit.metadata.services.baseopenstackservice [-] user_data metadata not present get_client_auth_certs C:\Program Files (x86)\Cloudbase Solutions\Cloudbase-Init\Py
thon27\lib\site-packages\cloudbaseinit\metadata\services\baseopenstackservice.py:144
2017-04-05 09:32:03.999 1408 INFO cloudbaseinit.plugins.windows.winrmcertificateauth [-] WinRM certificate authentication cannot be configured as a certificate has not been provided in the metadata
2017-04-05 09:32:03.999 1408 INFO cloudbaseinit.init [-] Executing plugin 'LocalScriptsPlugin'
2017-04-05 09:32:07.013 1408 DEBUG cloudbaseinit.osutils.windows [-] Stopping service cloudbase-init stop_service C:\Program Files (x86)\Cloudbase Solutions\Cloudbase-Init\Python27\lib\site-packages\cloudb
aseinit\osutils\windows.py:719
    .EXAMPLE 
    
# Get the last 1000 lines of console output from server named meta_test, and from that select the first 10 lines
    
PS C:\>Get-K5TTYConsole -token $token -servername meta_test -lines 1000 | select -First 10

[    0.000000] Initializing cgroup subsys cpuset
[    0.000000] Initializing cgroup subsys cpu
[    0.000000] Initializing cgroup subsys cpuacct
[    0.000000] Linux version 3.13.0-61-generic (buildd@lgw01-50) (gcc version 4.8.2 (Ubuntu 4.8.2-19ubuntu1) ) #100-Ubuntu SMP Wed Jul 29 11:21:34 UTC 2015 (Ubuntu 3.13.0-61.100-generic 3.13.11-ckt22)
[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-3.13.0-61-generic root=LABEL=cloudimg-rootfs ro console=tty1 console=ttyS0
[    0.000000] KERNEL supported cpus:
[    0.000000]   Intel GenuineIntel
[    0.000000]   AMD AuthenticAMD
[    0.000000]   Centaur CentaurHauls
[    0.000000] Disabled fast string operations

#>
    param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$servername = $(Display-Error -error "Please specify a server name using the -servername parameter"),
        [int]$lines = 50,
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $servername)) {break}
    try
    {
        $return = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["compute"])/servers" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy
        $serverid = (($return.Content | ConvertFrom-Json).servers | where name -eq $servername).id
        if (-not $serverid)
        {
            Display-Error -error "Get-K5TTYConsole - Server $servername not found."
        }
        $json = Get-K5JSON tty_console
        $return = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["compute"])/servers/$serverid/action" -Method POST -headers $token.token -Body $json -ContentType "application/json" -UseProxy $useProxy
        $output = ($return.content | ConvertFrom-Json).output -split "`n"
    }
    catch
    {
        Display-Error -error "Get-K5TTYConsole failed..." -errorObj $_
    }
    return $output
}

Function Get-K5WindowsPassword
{
    <#

    .SYNOPSIS
    Decrypt the automatically generated admin password for a given Windows server

    .DESCRIPTION
    The Get-K5WindowsPassword function decrypts the buid time auto generated  k5user administrative user's password using the
    private key associated with the server when it was built

    .PARAMETER token
    Required, a token object returned by the Get-K5Token function

    .PARAMETER key
    Required, path to the file containg the private key

    .PARAMETER useProxy
    Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

    .EXAMPLE 
    
# Get the decrypted k5user password from server named WinTest using proxy when making the call
    
PS C:\>Get-K5WindowsPassword -token $token -servername WinTest -key C:\Path\To\My\PrivateKey.pem -UseProxy

X672WKSztcYDtL9Tb6Raf

#>
    param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$servername = $(Display-Error -error "Please specify a server name using the -servername parameter"),
        [string]$key = $(Display-Error -error "Please specify the path to a private key file using the -key parameter"),
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $servername) -or (-not $key)) {break}
    try
    {
        $return = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["compute"])/servers" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy
        $serverid = (($return.Content | ConvertFrom-Json).servers | where name -eq $servername).id
        if (-not $serverid)
        {
            Display-Error -error "Server $servername not found."
        }
        $return = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["compute"])/servers/$serverid/os-server-password" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy
        $password = ($return.Content | ConvertFrom-Json).password
        $password | & cmd /c "$((Get-K5Vars)["OpenSSLPath"]) base64 -d -A | $((Get-K5Vars)["OpenSSLPath"]) rsautl -decrypt -inkey $key"
    }
    catch
    {
        Display-Error -error "Get-K5WindowsPassword failed..." -errorObj $_
    }
}
<#Following additional functions added by Steve Atherton (SPA) from 18 September 2017
Copy-K5VMtoImage
Remove-K5Image
Get-K5Volumes
New-K5ImageMember
Confirm-K5ImageMember
Get-K5ImageMembers
Get-K5ImageMemberDetails
Get-K5Images
Get-K5Objects
Import-K5OSImage
Get-K5Imports
New-K5Container
Remove-K5Container
Remove-K5Object
Get-K5AuthData
Set-K5CSVScope
New-K5Server
Remove-K5Server
Start-K5Server
Stop-K5Server
Restart-K5Server
New-K5Network
Remove-K5Network
New-K5SubNet
Remove-K5Subnet
New-K5Router
Remove-K5Router
New-K5RouterInterface
Remove-K5RouterInterface
Update-K5Router
#>
Function Copy-K5VMtoImage
{

<#

.SYNOPSIS
Clones an existing K5 VM to a private image

.DESCRIPTION
Clones a K5 Virtual Machine to local private image store. The image is cloned to the "RAW" Disk format and "BARE" container format.
Checks to see if the Image already exists and if so does not proceed. Also checks if the volume to be copied is already being copied (uploaded) and again does not proceed if it is

.PARAMETER token
Required, a token object for the transaction

.PARAMETER VolumeID
Required, the ID of the volume to be cloned

.PARAMETER ImageName
Required, the name of the image you wish to be created

.PARAMETER Force
Optional, specify True or False. If omitted it will default to 'false' which will only copy the VM if the disk is not in-use (i.e. attached to a VM) as it is the Block Storage Volume that is copied to the Image store

.PARAMETER useProxy
Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

.EXAMPLE

# 
The following script uses the Copy-K5VMtoImage Function by obtaining the Volume ID from a Gridview of VMs

         $MyVolume=Get-K5Volumes -token $token -UseProxy | Out-GridView -Title "Select a disk to Clone and press Enter or click OK" -PassThru 
         $Volume_ID=$MyVolume.VolumeID
         Copy-K5VMtoImage -token $token -VolumeID $Volume_ID -imageName MYCLONE -force $true -UseProxy

This script uses the function Get-K5Volumes (for brevity and because it shows the attached server) to show a list of volumes and the attached server. This is piped to a Gridview where the user can select a Volume.
    
After selecting a volume, the $Volume variable extracts the Volume ID and passes it to the Copy-K5VMtoImage function to create an image using that volume called MYCLONE.

If the Copy works, it will return the message:
    
          PS> Success! Image is uploading

When the list of volumes appear, check the status of the Volume you want to clone:
            
            'InUse' - means it can be cloned, but you will need to use the '-Force True' parameter (MAKE SURE THE VM IS SHUTDOWN!)
            'uploading' - means it is already being uploaded to an image and cannot be uploaded again at this moment
            'available' - means it is not attached to a VM and can be cloned without Force

If the status of the volume is 'uploading', the Function will throw an error:

If the Image Name already exists, the Function will throw an error:

          Error: Copy VM to Image failed...
          Exception: Image name already exists
          At C:\Users\athertonsp\Documents\Fujistu K5\k5-powershell-functions-master\k5funcs.ps1:875 char:10
          +         {throw "Image name already exists"
          +          ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

  NOTE - K5 allows duplicate names, but this function deliberately avoids having them!

          Error: Copy VM to Image failed...
          Exception: That volume is currently uploading to an image already. Use Get-K5Volumes to check status and try again later
          At C:\Users\athertonsp\Documents\Fujistu K5\k5-powershell-functions-master\k5funcs.ps1:883 char:14
          + ...            {throw "That volume is currently uploading to an image alr ...
          +                 ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#>
#v1.0 SPA 7/9/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$VolumeID = $(Display-Error -error "Please specify a Volume ID using the -VolumeID parameter"),
        [string]$imageName = $(Display-Error -error "Please specify a name for the image using the -ImageName parameter"),
        [bool]$Force,
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $VolumeID) -or (-not $imageName)) 
    {write-host "Required parameter missing"
    break}
    try
    {
     #Check to see if the image name already exists
        $target = $token.endpoints["image"] + "/v2/images"
        $in=Invoke-Webrequest2 -token $token -uri $target -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $iid=(($in.Content | Convertfrom-Json).images | where name -eq $imageName)
        If ($iid)
        {throw "Image name already exists"
        break}

     #Check if the volume is already uploading...
        $target2=$token.endpoints["blockstoragev2"] + "/volumes/" + $Volume_ID
        $detail=Invoke-Webrequest2 -token $token -Uri $target2 -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $output1 = (($detail.content | ConvertFrom-Json).volume | where status -eq "uploading")
        If ($output1)
            {throw "That volume is currently uploading to an image already. Use Get-K5Volumes to check status and try again later"
            break}

     #Check what the Force paramter is set to and default to false if it is not set. Also change case to lower for Json use
        If ($Force -eq $true)
            { $F='true' }
        Else
            { $F = 'false'}
        $cformat="bare"
        $dformat="raw"

        $json=Get-K5json cloneToImage
        $return=Invoke-Webrequest2 -token $token -uri "$($token.endpoints["blockstoragev2"])/volumes/$Volume_ID/action" -Method POST -headers $token.token -Body $json -ContentType "application/json" -Useproxy $useProxy
        $output = (($return.content | ConvertFrom-Json).'os-volume_upload_image')
        $output = $output.status
        $message = "Success! Image is $output"
    }
    catch
    {
    Display-Error -error "Copy VM to Image failed..." -errorObj $_
    $result = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($result)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $reader.ReadToEnd()
    }
    return $message
}
Function Remove-K5Image
{
<#

.SYNOPSIS
Deletes a private image from the K5 image store

.DESCRIPTION
Deletes an Image form the K5 Image Store. Use caution! This function does include an escape road and prompts the user for confirmation before deleting the selected image. 
Because Images can hacve dupliacte names, this function MUST use the Image Id, so you should consider using a script which provides a list of Images to select from (SEE EXAMPLE) by typing Get-Help Remove-K5Image -Examples.

.PARAMETER token
Required, a token object for the transaction

.PARAMETER ImageID
Required, the ID of the image to be deleted

.PARAMETER useProxy
Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

.PARAMETER Force
Optional, used to bypass confirmation of deletion (i.e. no confirmation prompt provided)

.EXAMPLE

# The following script uses the Remove-K5Image to present the list of images in GridView so that it can be selected and the Image ID passed to teh Remove-K5Image Function

            $MyImage=Get-K5Resources -token $token -type images -useProxy | Out-GridView -Title "Select an Image to DELETE and press Enter or click OK" -OutputMode Single 
            $Image_ID=$MyImage.id
            Remove-K5Image -token $token -ImageId $Image_ID -UseProxy

The Get-K5Resources Function is called and piped to a Gridview that allows the user to select an Image to delete. The selected Image is passed to the variable $MyImage and the Image ID extracted from it to the Variable $Image_ID.

The Image ID is then passed to the Remove-K5Image Function which prompts for confirmation:

            Delete the image 'MYCLONE1' - 'b0eb29dc-ceb9-4d9d-9d42-f6f6bdffb2a9'? Are you sure? - (Y \ N):

If you respond with 'n' or 'N', the function exits:

            Delete the image 'MYCLONE1' - 'b0eb29dc-ceb9-4d9d-9d42-f6f6bdffb2a9'? Are you sure? - (Y \ N): n
            Delete Cancelled!

By confirming with 'y' or 'Y', the Remove-K5Image Function deletes the image and returns a confirmation message:

            Delete the image 'MYCLONE1' - 'b0eb29dc-ceb9-4d9d-9d42-f6f6bdffb2a9'? Are you sure? - (Y \ N): y
            Image 'MYCLONE1' - 'b0eb29dc-ceb9-4d9d-9d42-f6f6bdffb2a9' Removed ... 


#>
#v1.0 SPA 6/9/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$ImageID = $(Display-Error -error "Please specify an Image ID using the -ImageID parameter"),
        [switch]$UseProxy,
        [switch]$Force
    )
    if ((-not $token) -or (-not $ImageID)) 
    {
    Write-Host "Required parameter missing"
    break
    }
    try
    {
     #Get the name of the Image   
        $target = $token.endpoints["compute"] + "/images/" + $ImageID
        $in=Invoke-Webrequest2 -token $token -uri $target -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $iid=(($in.Content | Convertfrom-Json).image)
        $iid = $iid.name
        
     #Ask for confirmation of deletion
        If ($Force)
        {$choice = "y"}
        Else
        {$choice = ""}
        while ($choice -notmatch "[y|n]")
        {$choice = read-host "Delete the image '$iid' - '$ImageID'? Are you sure? - (Y \ N)"}
          #If confirmed, delete the image
            if ($choice -eq "y")
            {
            $target=$token.endpoints["compute"] + "/images/" + $ImageID
            $return=Invoke-Webrequest2 -token $token -uri $target -Method DELETE -headers $token.token -ContentType "application/json" -Useproxy $useProxy
            $output = Write-Host "Image '$iid' - '$ImageId' Removed ... "
            }
          #Otherwise, just jumpt to return and do nothing
            Else
            {$output = Write-Host "Delete Cancelled!"
            break}
    }
    catch
    {
        Display-Error -error "Deleting the specified Image failed..." -errorObj $_
    }
    return $output
}
Function Get-K5Volumes
{
<#

.SYNOPSIS
Lists K5 volumes in Blockstorage. Shows Volume ID, Status and Attached Server Name

.DESCRIPTION
Different to Get-K5Resources as it provides the Volume IDs and the server name of the server they are attached to (if applicable). Useful before deleting a Volume!

.PARAMETER token
Required, a token object for the transaction

.PARAMETER useProxy
Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

.EXAMPLE

    #Get-K5Volumes -token $token -useProxy

    VolumeID                             Status    ServerName   
    --------                             ------    ----------   
    f1877b66-776e-4246-8083-f31a9e61aa5e in-use    Demo_Server_A
    3a97269d-943b-4745-9d51-ad97b1b0b2f4 in-use    Demo_Server_C
    f5a0e578-9e57-4f1e-9fae-e45d302698e4 in-use    Demo_Server_B
    ad489be7-9feb-44b8-8e30-ac76d4bcc4a4 uploading FOSPSVR03    
    4486eefd-5b98-41e0-bf6a-789d9a1056a4 uploading FOSPSVR02   


#>
#v1.0 SPA 7/9/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [switch]$UseProxy
    )
    if (-not $token) 
    {Write-Host "Required parameter missing..."
    break}
    try
    {
     #Go off and get the Volumes in Blockstorage...
        $target=$token.endpoints["blockstoragev2"] + "/volumes/detail"
        $detail=Invoke-Webrequest2 -token $token -Uri $target -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $output = ($detail.content | ConvertFrom-Json).volumes
     #Calculate how many volumes there are ...
        $x = $output.GetUpperBound(0)
     #Create an array to store the values in...
        $volumes = @()
        ForEach ($i in 0..$x)
            {
            $vols = New-Object PsObject
            $VolID = ($output.attachments).id[$i]
            $vstatus = ($output.status)[$i]
            $vols | add-member -name "VolumeID" -MemberType noteproperty -value $volid
            $vols | add-member -name "Status" -MemberType noteproperty -value $vstatus
         #Determine what servers are attached
            $svrid = ($output.attachments).server_id[$i]
         #If no server is attached, set it to Not Attached
                If ($svrid -eq "")
                { $svrid = "Not attached" }
            #Now cycle through the attached servers and get the name rather than the ID
                    ForEach ($id in $svrid)
                    {
                     If ($id -eq "Not attached")
                        { $vols | add-member -name "ServerName" -MemberType noteproperty -value "Not attached" -force
                        $volumes += $vols
                        }
                    Else
                        {
                        $target2 = $token.endpoints["compute"] + "/servers/" + $id
                        $getSvrName = Invoke-Webrequest2 -token $token -Uri $target2 -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
                        $svrname = ($getSvrName.Content | ConvertFrom-Json).server
                        $vols | add-member -name "ServerName" -MemberType noteproperty -value $svrname.name -force
                        $volumes += $vols
                        }
                    }
             }
    }         
    
    catch
    {
        Display-Error -error "Listing Volumes failed..." -errorObj $_
    }
    return $volumes
}
Function New-K5ImageMember
{
<#

.SYNOPSIS
Shares a Private VM image to another Project

.DESCRIPTION
A Private Image created in one Project, will not be visble to other projects unless it is shared to that Project. Once shared, the receiving Project still has to accept it.

This Function does the first bit and shares the Image to another project; you must be scoped to the Project where the image resides to run this function.

Once run, the status if the "Share" will be set to "Pending" until the receiving Project "accepts" it.

.PARAMETER token
Required, a token object for the transaction

.PARAMETER MemberID
Required, the ID of the Project to share the image to

.PARAMETER ImageID
Required, the ID of the Image to be shared

.PARAMETER useProxy
Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 


.EXAMPLE

       #PS C:\> New-K5ImageMember -Token $token -ImageID 0e76bca6-216c-46a7-a216-2e278b6f1b44 -MemberId ff47c8e08bd04764841d67ef76309383 -UseProxy

        status     : pending
        created_at : 2017-11-22T15:19:04Z
        updated_at : 2017-11-22T15:19:04Z
        image_id   : 0e76bca6-216c-46a7-a216-2e278b6f1b44
        member_id  : ff47c8e08bd04764841d67ef76309383
        schema     : /v2/schemas/member

#>
#v1.0 SPA 22/11/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$MemberID = $(Display-Error -error "Please specify a Project to share to using the -MemberID parameter"),
        [string]$ImageID = $(Display-Error -error "Please specify a Image ID using the -ImageID parameter"),
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $ImageID) -or (-not $MemberID)) {
    Write-Host "Required parameter missing"
    break}
    try
    {      
        $json=Get-K5json shareToProject
        $target = $token.endpoints["image"] + "/v2/images/" + $ImageID + "/members"
        $return=Invoke-Webrequest2 -token $token -uri $target -Method POST -headers $token.token -Body $json -ContentType "application/json" -Useproxy $useProxy
        $output = ($return.content | ConvertFrom-Json)
    }
    catch
    {
        Display-Error -error "Sharing the image another Project failed..." -errorObj $_
    }
    return $output
}
Function Confirm-K5ImageMember
{
<#

.SYNOPSIS
Accepts a Private VM image to that has been shared to a Project

.DESCRIPTION
A Private Image created in one Project, will not be visble to other projects unless it is shared to that Project. Once shared, the receiving Project still has to accept it.

The Function "New-K5ImageMember" does the first bit and shares the Image to another project.

This Function (Confirm-K5ImageMember) does the acceptance. It must be run from the project accepting the Image (i.e. you must be scoped to the receiving/accepting project) OR you must have the relevant permissions in the receiving Project to run it from elsewhere.

.PARAMETER token
Required, a token object for the transaction

.PARAMETER MemberID
Required, the ID of the Project accepting the image

.PARAMETER ImageID
Required, the ID of the Image being shared

.PARAMETER useProxy
Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 


.EXAMPLE

       #PS C:\> Confirm-K5ImageMember -Token $token -ImageID 0e76bca6-216c-46a7-a216-2e278b6f1b44 -MemberId ff47c8e08bd04764841d67ef76309383 -UseProxy

        
        created_at : 2017-11-22T15:19:04Z
        image_id   : 0e76bca6-216c-46a7-a216-2e278b6f1b44
        member_id  : ff47c8e08bd04764841d67ef76309383
        schema     : /v2/schemas/member
        status     : accepted
        updated_at : 2017-11-22T15:19:04Z
        
        
       

#>
#v1.0 SPA 22/11/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$MemberID = $(Display-Error -error "Please specify the ID of Project accepting the share using the -MemberID parameter"),
        [string]$ImageID = $(Display-Error -error "Please specify the Image to accept using the -ImageID parameter"),
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $ImageID) -or (-not $MemberID)) {
    Write-Host "Required parameter missing"
    break}
    try
    {      
        $json=Get-K5json confirmFromProject
        $target = $token.endpoints["image"] + "/v2/images/" + $ImageID + "/members/" + $MemberID 
        $return=Invoke-Webrequest2 -token $token -uri $target -Method PUT -headers $token.token -Body $json -ContentType "application/json" -Useproxy $useProxy
        $output = ($return.content | ConvertFrom-Json)
    }
    catch
    {
        Display-Error -error "Accepting the image failed..." -errorObj $_
    }
    return $output
}
Function Get-K5ImageMembers
{
<#

    .SYNOPSIS
    Lists the Projects able to access images that have been shared.

    .DESCRIPTION
    For any Private image in a Project that is shared to other Projects, this function will list all Projects to which that image is shared and the status (i.e. whether it has been accepted or not).
    
    .PARAMETER token
    Required, a token object for the transaction

    .PARAMETER ImageID
    Required, the ID of the Image to lookup the members of

    .PARAMETER useProxy
    Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

    .EXAMPLE

     #PS C:\> Get-K5ImageMembers -Token $token -ImageID 3d121a60-30e6-41bf-bd1b-d411011192db -UseProxy

     status     : accepted
    created_at : 2017-11-22T15:01:20Z
    updated_at : 2017-11-22T15:09:16Z
    image_id   : 3d121a60-30e6-41bf-bd1b-d411011192db
    member_id  : 9505d1dab17946ea97745d5de30cc8be
    schema     : /v2/schemas/member

    status     : accepted
    created_at : 2017-09-21T15:43:54Z
    updated_at : 2017-09-21T15:57:11Z
    image_id   : 3d121a60-30e6-41bf-bd1b-d411011192db
    member_id  : ff47c8e08bd04764841d67ef76309383
    schema     : /v2/schemas/member


#>
#v1.0 SPA 22/11/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$ImageID = $(Display-Error -error "Please supply the ID of the Image using the -ImageID parameter"),
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $ImageID))  
    {Write-Host "Required parameter missing"
    break}
    try
    {
        $target = $token.endpoints["image"] + "/v2/images/" + $ImageID + "/members"   
        $return=Invoke-Webrequest2 -token $token -uri $target -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $output = ($return.content | ConvertFrom-Json).members
    }
    catch
    {
        Display-Error -error "Listing Images failed..." -errorObj $_
    }
    return $output
}
Function Get-K5ImageMemberDetails
{
<#

    .SYNOPSIS
    Lists the Details for a specific Project that is sharing a specified Image.

    .DESCRIPTION
    For any Private image in a Project that is shared to other Projects, this function will show the details for a specific Project to which that image is shared and the status (i.e. whether it has been accepted or not).
    
    .PARAMETER token
    Required, a token object for the transaction

    .PARAMETER ImageID
    Required, the ID of the Image which is being shared

    .PARAMETER MemberID
    Reuqired, the ID of the Project for which you want the detail

    .PARAMETER useProxy
    Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

    .EXAMPLE

     #PS C:\> Get-K5ImageMemberDetails -Token $token -ImageID 3d121a60-30e6-41bf-bd1b-d411011192db -MemberID 9505d1dab17946ea97745d5de30cc8be -UseProxy

    status     : accepted
    created_at : 2017-11-22T15:01:20Z
    updated_at : 2017-11-22T15:09:16Z
    image_id   : 3d121a60-30e6-41bf-bd1b-d411011192db
    member_id  : 9505d1dab17946ea97745d5de30cc8be
    schema     : /v2/schemas/member



#>
#v1.0 SPA 22/11/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$ImageID = $(Display-Error -error "Please supply the ID of the Image using the -ImageID parameter"),
        [string]$MemberID = $(Display-Error -error "Please supply the ID of the Project using the -MemberID parameter"),
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $ImageID) -or (-not $MemberID))  
    {Write-Host "Required parameter missing"
    break}
    try
    {
        $target = $token.endpoints["image"] + "/v2/images/" + $ImageID + "/members/" + $MemberID   
        $return=Invoke-Webrequest2 -token $token -uri $target -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $output = ($return.content | ConvertFrom-Json)
    }
    catch
    {
        Display-Error -error "Listing Image details failed..." -errorObj $_
    }
    return $output
}
Function Get-K5Images
{

<#

    .SYNOPSIS
    Lists the images available in a Project. Same as Get-K5Resources '-type images' but presents information slightly differently

    .DESCRIPTION
    Shortened list of details of images, including optional '-Table' parameter to display subset of information in a powerShell table

    .PARAMETER token
    Required, a token object for the transaction

    .PARAMETER ImageName
    Optional, when viewing details of a specific image specify the Name of the Image (this gets converted to the ID via lookup)

    .PARAMETER Table
    Optional, switch parameter to specify whether or not to present the results as a PowerShell table showing only Name, Status, Visibility and ID

    .PARAMETER useProxy
    Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

    .EXAMPLE

     #PS C:\> Get-K5Images -Token $token -UseProxy

This will return a list of images as follows (only 2 images shown for brevity and example uses a proxy server):

            status            : active
            name              : FJK5-NAS-V02
            tags              : {}
            container_format  : bare
            created_at        : 2016-10-03T10:27:37Z
            disk_format       : qcow2
            updated_at        : 2016-10-03T10:27:38Z
            visibility        : public
            fcx.base_image_id : 0e330855-aeff-423c-99b2-7ee16adb5f68
            self              : /v2/images/0e330855-aeff-423c-99b2-7ee16adb5f68
            fcx.centos        : true
            protected         : True
            id                : 0e330855-aeff-423c-99b2-7ee16adb5f68
            file              : /v2/images/0e330855-aeff-423c-99b2-7ee16adb5f68/file
            checksum          : b1201abe04b85135ab35929ba38df84e
            owner             : 31ceb599e8ff48aeb66f2fd748988960
            min_disk          : 30
            size              : 1879900160
            min_ram           : 0
            schema            : /v2/schemas/image

            status            : active
            name              : CentOS 7.2 64bit (English) 01
            tags              : {}
            container_format  : bare
            created_at        : 2016-10-03T10:23:44Z
            disk_format       : qcow2
            updated_at        : 2016-10-03T10:23:45Z
            visibility        : public
            fcx.base_image_id : 58fd966f-b055-4cd0-9012-cf6af7a4c32b
            self              : /v2/images/58fd966f-b055-4cd0-9012-cf6af7a4c32b
            fcx.centos        : true
            protected         : True
            id                : 58fd966f-b055-4cd0-9012-cf6af7a4c32b
            file              : /v2/images/58fd966f-b055-4cd0-9012-cf6af7a4c32b/file
            checksum          : 72e90ec33fb5b91cf709e1f2010c4054
            owner             : 31ceb599e8ff48aeb66f2fd748988960
            min_disk          : 30
            size              : 1024983040
            min_ram           : 0
            schema            : /v2/schemas/image

    .EXAMPLE

    #PS C:\> Get-K5images -token $token -ImageName 'Windows Server 2012 R2 SE 64bit (English) 01' -useproxy 

Shows the details of one particular image, e.g. the Windows 2012 R2 01 Image and will return teh following:
        

            status            : active
            name              : Windows Server 2012 R2 SE 64bit (English) 01
            tags              : {}
            container_format  : bare
            created_at        : 2016-10-03T11:09:02Z
            disk_format       : qcow2
            updated_at        : 2016-10-03T11:09:03Z
            visibility        : public
            fcx.base_image_id : 6e1610db-1115-4260-8dc2-bcdd526a54be
            self              : /v2/images/6e1610db-1115-4260-8dc2-bcdd526a54be
            min_disk          : 80
            protected         : True
            id                : 6e1610db-1115-4260-8dc2-bcdd526a54be
            file              : /v2/images/6e1610db-1115-4260-8dc2-bcdd526a54be/file
            checksum          : 56a7fca10e650e7510cdd75012167095
            owner             : 31ceb599e8ff48aeb66f2fd748988960
            size              : 15858139136
            fcx.win           : true
            min_ram           : 0
            schema            : /v2/schemas/image

    .EXAMPLE

    #PS C:\> Get-K5Images -token $token -UseProxy -Table

To view the information in a PowerShell table showing only the Image Name, ID, Status and visibility use the -Table parameter:


    Image                                              Status   ID                                     Visibility
    -----                                              ------   --                                     ----------
    SPACLONE6                                          saving   b0eb29dc-ceb9-4d9d-9d42-f6f6bdffb2a9   private   
    SPACLONE5                                          active   c742526b-b52a-4dac-a769-5655740ddfb9   private   
    SPACLONE1                                          active   f1a031ec-1bf0-4af1-a26c-38f042f816b5   private   
    Windows Server 2008 R2 SE SP1 64bit (English) 02   active   522111c2-efea-4b89-bc28-a56026f62702   public    
    Windows Server 2012 R2 SE 64bit (English) 02       active   54b8b36a-c33b-4e9f-a302-2268269a7649   public    
    CentOS 7.3 64bit (English) 01                      active   a0fe2e71-acb9-479d-b7f9-0270d1ef4fb1   public    
    Ubuntu Server 16.04 LTS (English) CTO              active   948d1058-77a6-4fe8-8d9e-19f7e2a8c18b   private   
    


#>
#v1.0 SPA 6/9/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$ImageName,
        [switch]$Table,
        [switch]$UseProxy
    )
    if (-not $token) 
    {Write-Host "Required parameter missing"
    break}
    try
    {
        If ($ImageName)
        {
        $target = $token.endpoints["image"] + "/v2/images"
        $in=Invoke-Webrequest2 -token $token -uri $target -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $iid=(($in.Content | Convertfrom-Json).images | Where Name -eq $ImageName).id
        $target1 = $token.endpoints["image"] + "/v2/images/" + $iid
        $return=Invoke-Webrequest2 -token $token -uri $target1 -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $output = $return.content | convertfrom-json
            If ($Table)
            {
            $tableview = @()
                ForEach ($image in $output)
                {
                $NewTable = New-Object PSObject
                $NewTable | Add-Member -MemberType NoteProperty -Name "Image" -Value $image.name
                $NewTable | Add-Member -MemberType NoteProperty -Name "Status" -Value $image.status
                $NewTable | Add-Member -MemberType NoteProperty -Name "ID" -Value $image.id
                $NewTable | Add-Member -MemberType NoteProperty -Name "Visibility" -Value $image.visibility
                $tableview += $NewTable
                } 
            $output = $tableview
            }
        }
        Else
        {$target = $token.endpoints["image"] + "/v2/images"        
        $return=Invoke-Webrequest2 -token $token -uri $target -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $output = $return.content | convertfrom-json
        $output = $output.images
            If ($Table)
            {
            $tableview = @()
                ForEach ($image in $output)
                {
                $NewTable = New-Object PSObject
                $NewTable | Add-Member -MemberType NoteProperty -Name "Image" -Value $image.name
                $NewTable | Add-Member -MemberType NoteProperty -Name "Status" -Value $image.status
                $NewTable | Add-Member -MemberType NoteProperty -Name "ID" -Value $image.id
                $NewTable | Add-Member -MemberType NoteProperty -Name "Visibility" -Value $image.visibility
                $tableview += $NewTable
                } 
            $output = $tableview
            }
        }
    }
    catch
    {
        Display-Error -error "Listing Images failed..." -errorObj $_
    }
    return $output
}
Function Get-K5Objects
{
<#

.SYNOPSIS
Displays Objects in a selected Container in the Object Store of a Project

.DESCRIPTION
Object Storage consists of Containers and Objects within Containers. This Function lists all the Objects contained within a specified Container.

.PARAMETER token
Required, a token object for the transaction

.PARAMETER Container
Required, the Container name with the objects to list

.PARAMETER useProxy
Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used

.EXAMPLE

      #PS C:\>Get-K5Objects -token $token -Container MYCONTAINER -UseProxy

        MyDisk-disk1.vmdk
        MyDisk-disk1.vmdk-000000
        MyDisk-disk1.vmdk-000001
        MyDisk-disk1.vmdk-000002
        MyDisk-disk1.vmdk-000003
        MyDisk-disk1.vmdk-000004
    
 
#>
#v1.0 SPA 7/9/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$Container = $(Display-Error -error "Please specify a Conatainer Name using the -Container parameter"),
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $Container)) {
    Write-Host "Required Parameter missing"
    break}
    try
    {
    $endpoint = $token.endpoints["objectstorage"]
     $detail = Invoke-WebRequest2 -token $token -Uri "$($endpoint)/$($Container)?format=json" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy | convertfrom-json
       $return = @()
                   foreach ($object in $detail)
                        {
                         $return += $object.name
                        }
    }
    catch
    {
    Display-error -error "Listing container objects failed ..." -errorObj $_
    }
    return $return
}
Function Import-K5OSImage
{
<#

.SYNOPSIS
Using the K5 Image Import feature, this function imports and registers a selected disk image in the Object Store, to the current K5 Project Image Store

.DESCRIPTION
Imports and registers an image from the Object Store. The image will then appear in Compute > Images and be available to build VMs. See the "Virtual Server Import" section of the "IaaS Features Handbook" for more information on preparing and importing images. This function outputs a unique reference whcih can be used to view import progress using "Get-K5Imports".
The Function also checks whether the Image Name requested already exists and if it does, the Function throws an error and stops. Whilst K5 will actually allow duplicate image names (they will have unique IDs), but in practice this can cause problems determining what to use or delete, etc.

Currently, this function does not support the optional API parameters "checksum", "id", "kms" or "server_info".

.PARAMETER token
Required, a token object for the transaction

.PARAMETER ImageName
Required, the name you wish to give to the Image when it is imported

.PARAMETER ImageLocn
Required, the location (in Object Storage) of the object (manifest) file of the image to be imported. The location must be provided as the relative path of the "objectstorage" endpoint (v1/AUTH_projectid/container/object)

.PARAMETER MinMem
Optional, the minimum amount of RAM (in MB) that new VMs must have when building VMs from this image. If left blank, the minimum will be 0; the minimum K5 flavor provides 512MB

.PARAMETER MinDisk
Required, The minimum disk size (in GB) that new VMs must be when building VMs from this image

.PARAMETER OSType
Required, the OS Type in the format required by K5 e.g. win2012R2SE, win2008R2EE, rhel7, etc. Approved types are listed in the IaaS features Handbook.

.PARAMETER useProxy
Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

.EXAMPLE

        #PS C:\>Import-K5OSImage -token $token -imageName MyWindowsImage -imageLocn v1/AUTH_MyProjectID/MyContainer/MyImage.vmdk -OSType win2012R2SE -MinMem 1024 -MinDisk 66 -Activate false -UseProxy

        import_id                           
        ---------                           
        8da2f0ca-8bed-4d66-8b79-159cbede41ca


This imports an image file MyImage.vmdk (from the "MyContainer" object store in the configured Project) of type Windows 2012R2 Standard, with minimum RAM of 1GB and Minimum Disk size of 66GB

$Token uses the Project scoped in "K5env.csv".

The image will be imported as "MyWindowsImage" of type Windows 2012R2 Standard Edition. 

The Function returns the Import ID which can be used in the Function 'Get-K5Imports'

For example:

        PS C:\> Get-K5Imports -token $token -importID 8da2f0ca-8bed-4d66-8b79-159cbede41ca -UseProxy

                conversion       : True
                name             : MyWindowsImage
                container_format : bare
                min_ram          : 2048
                ovf_location     : 
                disk_format      : raw
                location         : /v1/AUTH_3a2ece588b1d412c82ebd7e165dcf172/MyContainer/MyImage-disk1.vmdk
                min_disk         : 66
                progress         : 0
                os_type          : win2012R2SE
                id               : c4df206c-6220-4201-9c45-5e8e23303575
                import_status    : processing

The output shows in this example, that the import is being 'processed'
 
#>
#v1.4 SPA 21/11/2017 - "If True" test on a boolean fails if the value is $false! So removed $activate from test for now. 22/11/17 - activate no longer in api list so deleted!
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$imageName = $(Display-Error -error "Please specify a name for the Image using the -imageName parameter"),
        [string]$imageLocn = $(Display-Error -error "Please specify an image file to import using the -imageLocn parameter"),
        [int]$minMem,
        [int]$minDisk = $(Display-Error -error "Please specify Minimum disk size in GB using the -MinDisk parameter"),
        [string]$OSType = $(Display-Error -error "Please specify an image using the -OSType parameter"),
        #[bool]$activate = $(Display-Error -error "Please state '$true' or '$false' to activate the KMS license activation using the -Activate parameter"),
        [switch]$UseProxy
    )
        if ((-not $token) -or (-not $ImageName) -or (-not $ImageLocn) -or (-not $MinDisk) -or (-not $OSType)) 
        {
        Write-Host "Required parameter missing"
        break}
    try
    {
     #Check to see if the image name already exists
        $target = $token.endpoints["image"] + "/v2/images"
        $in=Invoke-Webrequest2 -token $token -uri $target -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $iid=(($in.Content | Convertfrom-Json).images | where name -eq $imageName)
        If ($iid)
        {throw "Image name already exists"
        break}
        Else
        {
           <#Remarked out 22/11/17 - activate no longer required
           Handle the boolean case issue for Json
            If ($activate -eq $true)
            {$a = 'true'}
            If ($activate -eq $false)
            {$a = 'false'}#>

        $json=Get-K5json RegObjStore
        
        $target=$token.endpoints["vmimport"] + "/v1/imageimport"
        $return=Invoke-Webrequest2 -token $token -uri $target -Method POST -headers $token.token -Body $json -ContentType "application/json" -Useproxy $useProxy
        $output = ($return.content | ConvertFrom-Json)
        }
    }
    Catch
    {
    #Display-error -error "Could not import and register image ..." -errorObj $_
    $result = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($result)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $reader.ReadToEnd()

    }
    return $output
}
Function Get-K5Imports
{
<#

.SYNOPSIS
View the status of images imported to K5 using "Import-K5OSImage"

.DESCRIPTION
Having imported an image file from the object store using the function "Import-K5OSImage", this function will show the status of the import. 
If you provide an Image ID using the "imageID" parameter, it will only display the status of that particular import. If you do not provide an Image ID, it will display the status of all imports.

.PARAMETER token
Required, a token object for the transaction

.PARAMETER ImportID
Optional, The ID of the import to view the status of. Leave blank to view the status of all imports.

.PARAMETER useProxy
Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

.EXAMPLE

#       PS C:\> Get-K5Imports -token $token -UseProxy

This will return a list of all imports:-

        import_id                              import_status
        ---------                              -------------
        43f9ac99-b7f5-4b88-a8db-c5e8f6e70517   processing   
        4bfcf926-179a-454e-b315-2f633669452b   succeeded    
        e5bcf1ee-354d-44f0-9c6e-6cedbcea9fae   succeeded    
        d3fa62d6-8ea7-41d5-aa7c-04dcef3dc3ce   succeeded    
        685cdb55-a3e9-446f-b195-7721dbaa3437   succeeded  

.EXAMPLE

#       PS C:\> Get-K5Imports -token $token -importID 8da2f0ca-8bed-4d66-8b79-159cbede41ca -UseProxy

                conversion       : True
                name             : MyWindowsImage
                container_format : bare
                min_ram          : 2048
                ovf_location     : 
                disk_format      : raw
                location         : /v1/AUTH_3a2ece588b1d412c82ebd7e165dcf172/MyConatainer/MyImage-disk1.vmdk
                min_disk         : 66
                progress         : 0
                os_type          : win2012R2SE
                id               : c4df206c-6220-4201-9c45-5e8e23303575
                import_status    : processing

This will return just the status of the image import with the ID of 43f9ac99-b7f5-4b88-a8db-c5e8f6e70517:-

#>
#v1.0 SPA 7/9/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$importID,
        [switch]$UseProxy
    )
        if (-not $token) 
        {Write-Host "Required paarmeter missing"
        break}
    try
    {
        If ($importID) 
        {$target = $token.endpoints["vmimport"] + "/v1/imageimport/" + $importID + "/status"
        $detail=Invoke-Webrequest2 -token $token -uri $target -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $output = ($detail.content | convertfrom-json)
        $output = $output
        }
        Else 
        {$target=$token.endpoints["vmimport"] + "/v1/imageimport"
        $detail=Invoke-Webrequest2 -token $token -uri $target -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $output = ($detail.content | convertfrom-json)
        $output = $output.imports | select import_id, import_status
        }
    }
    Catch
    {
    Display-error -error "Could not list registered imports ..." -errorObj $_
    }
    return $output
    
}
Function New-K5Container
{
<#

.SYNOPSIS
Creates a K5 Container in K5 Object Storage of teh currently scoped project

.DESCRIPTION
Object Storage requires a container ("Folder") to be created in which to store objects ("Files"). This command creates a Container of the name as provided with the -Conatainer parameter in the currently scoped Project.
The Command returns Status code "201" when successful

                    StatusCode        : 201
                    StatusDescription : Created
                    Content           : 
                    RawContent        : HTTP/1.1 201 Created
                                        X-Fcx-Endpoint-Request: EXECUTED_REQ004479936_201
                                        X-Trans-Id: tx61d34743558c42e7b9b94-00598b11d9
                                        Content-Length: 0
                                        Content-Type: text/html;charset=UTF-8
                                        Date: Wed, 09 Aug 201...
                    Forms             : {}
                    Headers           : {[X-Fcx-Endpoint-Request, EXECUTED_REQ004479936_201], [X-Trans-Id, tx61d34743558c42e7b9b94-00598b11d9], [Content-Length, 0], 
                                        [Content-Type, text/html;charset=UTF-8]...}
                    Images            : {}
                    InputFields       : {}
                    Links             : {}
                    ParsedHtml        : mshtml.HTMLDocumentClass
                    RawContentLength  : 0

.PARAMETER token
Required, a token object for the transaction

.PARAMETER Container
Required, the name of the container to create

.PARAMETER useProxy
Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

.EXAMPLE

#         PS C:\> New-K5Container -token $token -Container MyContainer -useproxy

This creates a Container called "MyContainer" (in the current project specified in teh K5ENV.CSV file) and when successfully created, the Output from this will be:-

                    StatusCode        : 201
                    StatusDescription : Created
                    Content           : 
                    RawContent        : HTTP/1.1 201 Created
                                        X-Fcx-Endpoint-Request: EXECUTED_REQ004479936_201
                                        X-Trans-Id: tx61d34743558c42e7b9b94-00598b11d9
                                        Content-Length: 0
                                        Content-Type: text/html;charset=UTF-8
                                        Date: Wed, 09 Aug 201...
                    Forms             : {}
                    Headers           : {[X-Fcx-Endpoint-Request, EXECUTED_REQ004479936_201], [X-Trans-Id, tx61d34743558c42e7b9b94-00598b11d9], [Content-Length, 0], 
                                        [Content-Type, text/html;charset=UTF-8]...}
                    Images            : {}
                    InputFields       : {}
                    Links             : {}
                    ParsedHtml        : mshtml.HTMLDocumentClass
                    RawContentLength  : 0

#>
#v1.0 SPA 7/9/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$container = $(Display-Error -error "Please specify a Container name using the -container parameter"),
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $container)) 
    {Write-Host "Required parameter is missing ..."
    break}
    try
    {
        $target=$token.endpoints["objectstorage"] + "/" + $container
        $return=Invoke-Webrequest2 -token $token -uri $target -Method PUT -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $output = $return
    }
    catch
    {
        Display-Error -error "Create new Container failed..." -errorObj $_
    }
    return $output
}
Function Remove-K5Container
{
<#

.SYNOPSIS
Deletes a K5 Container from Object Storage

.DESCRIPTION
Deletes the specified Container having first prompted for confirmation. Answering No when asked will cancel the deletion.
NOTE that the container cannot be deleted if there are still objects in it. Use Remove-K5Object to remove any objects before deleting the container.
This command will fail if the Container is not empty.

.PARAMETER token
Required, a token object for the transaction

.PARAMETER container
Required, the name of the container to be deleted

.PARAMETER useProxy
Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

.PARAMETER Force
Optional, used to bypass confirmation of deletion (i.e. no confirmation prompt provided)

#>
#v1.0 SPA 7/9/2017 
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$container = $(Display-Error -error "Please specify a Container name using the -container parameter"),
        [switch]$UseProxy,
        [switch]$Force
    )
    if ((-not $token) -or (-not $container)) 
    {
    Write-Host "Required parameter is missing"
    break
    }
    #Ask for confirmation to delete the spcified container
    If ($Force)
    {$choice = "y"}
    Else
    {$Choice=""}
    While ($Choice -notmatch "[y|n]")
    {$Choice = Read-Host "Delete Container '$container'? Are you sure? (Y / N)"}
        If ($Choice -eq "n")
        {Write-Host "Delete cancelled!"
        Break}
    try
    {
    #Test if there are objects in the container
    $target=$token.endpoints["objectstorage"] + "/" + $container + "?format=json"
    $testObj = Invoke-WebRequest2 -token $token -Uri $target -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy | convertfrom-json
    $tested = @()
       foreach ($object in $testObj)
             { $tested += $object.name }             
            If ($tested -gt 0)
            {
            Write-Host "Container is not empty. Delete all objects before deleting the container"
            }
            Else
            {
            $target=$token.endpoints["objectstorage"] + "/" + $container
            $return=Invoke-Webrequest2 -token $token -uri $target -Method DELETE -headers $token.token -ContentType "application/json" -Useproxy $useProxy
            $output = $return}      
            }
    catch
    {
        Display-Error -error "Deleting the Container failed..." -errorObj $_
    }
    return $output
}
Function Remove-K5Object
{
<#
.SYNOPSIS
Deletes a specified object in a specified K5 Container in the K5 Object Storage of the currently scoped Project

.DESCRIPTION
Deletes an Object ("File") in a specified container. NOTE this function does NOT ask for confirmation before deleting objects

To delete multiple objects in a container, use this function with a script with a 'ForEach' statement (See Example 2) and you can select and delete multiple Objects.

Use this Function to delete objects from a container before you can delete the container.

.PARAMETER token
Required, a token object for the transaction

.PARAMETER Container
Required, the name of the container holding the object that is to be deleted

.PARAMETER Object
Required, the object to be deleted

.PARAMETER useProxy
Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 


.EXAMPLE

#        PS C:\> Remove-K5objects -token $token -Container MyContainer -Object MyText.txt -useproxy

Simply deletes the object 'MyText.txt' in the container 'MyContainer'



.EXAMPLE

# 
If you use this Function in a script with get-K5Resources" and a "ForEach" statement, you can select and delete multiple objects: For example:-
 
    $Container = Get-K5Resources -token $token -type containers -UseProxy | Out-GridView -Title "Select a container to delete objects from and press Enter or click OK" -PassThru 
    $ObjName = $Container.name
    $imageFile=Get-K5Objects -token $token -Container $ObjName -UseProxy | Out-GridView -Title "Select an object or objects (Ctl-Click) and press Enter or click OK" -PassThru 
    foreach($object in $imagefile) 
    {
    Remove-K5object -token $token -Container $objName -Object $object -useproxy
    }

This script will first show the available Containers in a GridView. You select the "Container" in the table that holds the objects you want to delete and click "OK". The Container name is passed to the $ObjName parameter
The Container Name variable is then used in the "Get-K5Objects" function to display a list of files in the container. Again this is output in Grid View in the script; select the file or files (Ctrl-Click or Sh-Click) to delete and click "OK".
The selected objects are then removed one by one using the "Remove-K5Object" Function.
#>
#v1.0 SPA 7/9/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$container = $(Display-Error -error "Please specify the Container name using the -Container parameter"),
        [string]$object = $(Display-Error -error "Please specify the Object to be deleted using the -Object parameter"),
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $container) -or (-not $object)) {
    Write-Host "A required parameter is missing"
    break}
    try
    {
        $target=$token.endpoints["objectstorage"] + "/" + $container + "/" + $object
        
        $return=Invoke-Webrequest2 -token $token -uri $target -Method DELETE -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $output = $return
    }
    catch
    {
        Display-Error -error "Delete Container failed..." -errorObj $_
    }
    return $output
}
Function Get-K5AuthData
{
<#

.SYNOPSIS
Show the information in K5ENV.CSV

.DESCRIPTION
Displays the current settings in the K5env.csv file used by the current session K5 PowerShell Functions

NOTE this will show the password in clear text so BE CAREFUL when using it!

There are no parameters required or usable with this Function

.EXAMPLE

#         PS C:\ Get-K5AuthData

                name,value
                k5user,user1
                k5pword,password1234
                k5project,myprojecta
                proxyURL,http://192.168.0.224:8080
                k5_uk_contract,MyConTra6t
                k5_de_contract,de_contract
                k5_fi_contract,fi_contract
                OpenSSLPath,"C:\GnuWin32\bin\openssl.exe"

Displaying the information in K5ENV.CSV. 

#>
#v1.0 SPA 7/9/2017

    $csvFile = "$PSScriptRoot\K5env.csv"
    Get-Content $csvFile

}
Function Set-K5CSVScope
{
<#

.SYNOPSIS
Change the currently scoped Project settings in K5ENV.CSV

.DESCRIPTION
Use this function to change the "k5project" value in the K5env.csv file. Specify the new value using the parameter "NewScope". The current value is read in by the function itself and then replaced with the new value.
You will need to get a new token after changing the Project in use!

NOTE that this asumes that the Project is in the same Contract and that all username and password information is the same.

.PARAMETER NewScope
Required, the name of the project you wish to change the value to. 

.EXAMPLE
#       PS C:\> Set-K5CSVScope -NewScope myprojectB
        
        Changed Project to myprojectB. Don't forget to obtain a new token

Changes the value in 'K5project' to 'myprojectB'.


        PS C:\> Set-K5CSVScope -NewScope myprojectA

        Changed Project to myprojectA. Don't forget to obtain a new token

Changes the value in 'K5project' to 'myprojectA'.

#>
#v1.0 SPA 7/9/2017
Param
    (
    [string]$NewScope = $(Display-Error -error "Please supply the string to be inserted -NewScope parameter")
    )
    if (-not $NewScope) {break}
    try
    {
    $strIn = $((Get-K5Vars)["k5project"])
    $csvFile = "$PSScriptRoot\K5env.csv"
    $strIn
    $csvFile

    (Get-Content $csvFile) -replace $strIn,$NewScope | out-file $csvFile 
    }
Catch
    {
    Display-error -error "Could not change Project in K5ENV.CSV ..." -errorObj $_
    }
return Write-Host "Changed Project to $NewScope. Don't forget to obtain a new token"
}
Function New-K5Server
{
<#

.SYNOPSIS
Creates a K5 Server

.DESCRIPTION
This function is probably best used with a script which obtains ID values for input into the function itself, using other K5 powerShell functions.

Useful for building basic servers. NOTE Server Name MUST BE UNIQUE or the Function will fail.

This Function creates a new server with a Boot Index of 0.

.PARAMETER token
Required, a token object for the transaction

.PARAMETER Server
Required, the name of the Server to create

.PARAMETER AZ
Required, the Availability Zone in which to create the server (for example uk-1a, uk-1b, etc.)

.PARAMETER Flavor
Required, the K5 Server Flavor ID or type. For example the S1 server type has an ID of 1101.

.PARAMETER Source
Required, whether the server is to be created from an existing K5 'image', 'volume' or 'snapshot' (MUST be lower case)

.PARAMETER Image
Required, the ID of the Image, Volume or Snapshot to create the server from

.PARAMETER Disk
Required, the OS disk size (in GB). Make sure it is equal to or bigger than the minimum permitted if applicable 

.PARAMETER Device
Required, the Disk Device. For example /dev/vda, /dev/vdb, etc.

.PARAMETER Network
Required, the network to create the server on

.PARAMETER KeyPair
Required, the keypair to be used for example for the Windows Password decryption or SSH access

.PARAMETER SecurityGroup
Optional, the Security Group to use to control protocol access rules. If not specified, Default Security Group is used

.PARAMETER DelOnterminate
Optional, whether to delete the volume created with the VM when the VM itself is deleted. Unlike official API, tshi is set to "True" by default

.PARAMETER useProxy
Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

.EXAMPLE

#        PS C:\> New-K5Server -token $token -AZ uk-1b -server MyServer01 -Flavor 1101 -Source image -Image 572b7420-3c6e-48e9-9728-c4d914037bf4 -Disk 70 -Device /dev/vda -Network ef62762d-14bc-4bd7-9e82-c05a51eea90f -KeyPair MyKey -SecurityGroup MyGroup -useproxy

         Server with ID '7ef01a4c-f8d8-47f6-be41-66935d11cf31' submitted for creation

Shows the successful creation of server "MyServer01". In truth the request is submitted to the build queue - use the Get-K5Resources to view status:

        PS C:\> Get-K5Resources -token $token -type server -name MyServer01 -detailed -useProxy

        status                               : BUILD
        updated                              : 2017-09-07T15:42:50Z
        hostId                               : 3ccbf25e18d487c6a2be069e141ead879ea5e695bc7b2ff240fda5e1
        OS-EXT-SRV-ATTR:host                 : gb1b01-pgy051-00
        addresses                            : @{LanB=System.Object[]}
        links                                : {@{href=http://10.23.0.201/v2/3a2ece588b1d412c82ebd7e165dcf172/servers/277ada34-20fe-446e-b5ea-baf2f
                                               a45b95d; rel=self}, @{href=http://10.23.0.201/3a2ece588b1d412c82ebd7e165dcf172/servers/277ada34-20fe
                                               -446e-b5ea-baf2fa45b95d; rel=bookmark}}
        key_name                             : MyKey
        image                                : 
        OS-EXT-STS:task_state                : 
        OS-EXT-STS:vm_state                  : build
        OS-EXT-SRV-ATTR:instance_name        : instance-00024183
        OS-SRV-USG:launched_at               : 2017-09-07T15:42:50.000000
        OS-EXT-SRV-ATTR:hypervisor_hostname  : gb1b01-pgy051-00
        flavor                               : @{id=1101; links=System.Object[]}
        id                                   : 277ada34-20fe-446e-b5ea-baf2fa45b95d
        security_groups                      : {@{name=MyGroup}}
        OS-SRV-USG:terminated_at             : 
        OS-EXT-AZ:availability_zone          : uk-1b
        user_id                              : bbf199e79a324572ad03c1f0fc0aa4f4
        name                                 : MyServer01
        created                              : 2017-09-07T15:37:32Z
        tenant_id                            : 3a2ece588b1d412c82ebd7e165dcf172
        OS-DCF:diskConfig                    : MANUAL
        os-extended-volumes:volumes_attached : {@{id=a5b73327-c42c-4145-bc93-d0e0fdebb473}}
        accessIPv4                           : 
        accessIPv6                           : 
        progress                             : 0
        OS-EXT-STS:power_state               : 1
        config_drive                         : 
        metadata                             : 
        self                                 : https://compute.uk-1.cloud.global.fujitsu.com/v2/3a2ece588b1d412c82ebd7e165dcf172/servers/277ada34-2
                                               0fe-446e-b5ea-baf2fa45b95d


#>
#v1.0 SPA 7/9/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$server = $(Display-Error -error "Please specify a Server name using the -Server parameter"),
        [string]$AZ= $(Display-Error -error "Please specify an Availability Zone using the -AZ parameter (e.g. uk-1a, uk1b, etc)"),
        [string]$flavor= $(Display-Error -error "Please specify a VM Server Type ID using the -Flavor parameter"),
        [string]$source= $(Display-Error -error "Please specify an OS boot disk source (Image, Volume or Snapshot) using the -Source parameter"),
        [string]$Image= $(Display-Error -error "Please provide the ID of the Volume to use as the source using the -Image parameter"),
        [string]$Disk= $(Display-Error -error "Please state the required disk size in GB using the -Disk parameter"),
        [string]$device= $(Display-Error -error "Please specify the disk device type (e.g. /dev/vda, /dev/vdb, etc) using the -Device parameter"),
        [string]$network= $(Display-Error -error "Please specify the Network ID using the -Network parameter"),
        [string]$KeyPair= $(Display-Error -error "Please supply a Key Pair name using the -KeyPair parameter"),
        [string]$securityGroup,
        [bool]$DelOnTerminate,
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $server) -or (-not $AZ) -or (-not $flavor) -or (-not $source) -or (-not $Image) -or (-not $Disk) -or (-not $device) -or (-not $network) -or (-not $keypair)) 
    {Write-Host "Required parameter missing"
    break}
    try
    {
        If (!($securityGroup))
            {$SecurityGroup = "Default Security Group"}

        If (!($DelOnTerminate))
            {$DelOnTerminate = $true}

        $target1=$token.endpoints["compute"] + "/servers"
        $return1=Invoke-Webrequest2 -token $token -uri $target1 -Method GET -headers $token.token -ContentType "application/json" -Body $json -Useproxy $useProxy
        $SvrUnique = (($return1.Content | Convertfrom-Json).servers | where name -eq $server)
        If ($svrunique)
        {Write-Host "Server Name is in use, please use a unique one! Use 'Get-K5Resources' with the '-Servers' parameter to see a list"
        break}
    #Just in case the source is in anything other than lower case
        $source = $source.tolower()
        $netUUID = $network
        $json = Get-K5Json NewServer
        
        $target=$token.endpoints["compute"] + "/servers"
        $return=Invoke-Webrequest2 -token $token -uri $target -Method POST -headers $token.token -ContentType "application/json" -Body $json -Useproxy $useProxy
        $output=($return | convertfrom-json).server
        $NewID = $output.id
        $message = "Server with ID '$NewID' submitted for creation" 
    }
    catch
    {
    throw
    $result = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($result)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $reader.ReadToEnd()
    
    }
    return $message
}
Function Remove-K5Server
{
<#

.SYNOPSIS
Deletes a K5 Server

.DESCRIPTION
Deletes a K5 server. Since Server Names may not be unique, this Function requires the ID of the Server so it may be best to use a script to find the ID first.

This Function will prompt for confirmation of the server to be deleted.

.PARAMETER token
Required, a token object for the transaction

.PARAMETER ServerID
Required, the K5 ID of the Server to delete

.PARAMETER useProxy
Optional

.PARAMETER Force
Optional, used to bypass confirmation of deletion (i.e. no confirmation prompt provided)

.EXAMPLE

#      PS C:\> Remove-K5Server -token $token -ServerID ef62762d-14bc-4bd7-9e82-c05a51eea90f -UseProxy

               Delete the Server 'MYSERVER'? Are you sure? - (Y \ N): y
               Server 'MYSERVER' deleted

The above deltes the server MYSERVER with the ID ef62762d-14bc-4bd7-9e82-c05a51eea90f

#      PS C:\> Remove-K5Server -token $token -ServerID ef62762d-14bc-4bd7-9e82-c05a51eea90f -UseProxy

               Delete the Server 'MYSERVER'? Are you sure? - (Y \ N): n
               Delete Cancelled!

If the deletion is cancelled by the user, the delete is cancelled


#>
#v1.0 SPA 08/09/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$serverid = $(Display-Error -error "Please specify the Server ID using the -ServerID parameter"),
        [switch]$UseProxy,
        [switch]$Force
    )
    if ((-not $token) -or (-not $serverid)) {break}
    try
    {
    #Find the name of the server
        $target1=$token.endpoints["compute"] + "/servers/" + $serverid
        $return1=Invoke-Webrequest2 -token $token -uri $target1 -Method GET -headers $token.token -ContentType "application/json" -Body $json -Useproxy $useProxy
        $SvrName = (($return1.Content | Convertfrom-Json).server).name
     #Ask for confirmation of deletion
        If ($Force)
        {$choice = "y"}
        Else
        {$choice = ""}
        while ($choice -notmatch "[y|n]")
        {$choice = read-host "Delete the Server '$SvrName'? Are you sure? - (Y \ N)"}
          #If confirmed, delete the server
            if ($choice -eq "y")
        {
        $target=$token.endpoints["compute"] + "/servers/" + $serverid
        $return=Invoke-Webrequest2 -token $token -uri $target -Method DELETE -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $output=Write-Host "Server '$SvrName' deleted" 
        }
        Else
        {$output = Write-Host "Delete Cancelled!"
        break}
    }
    catch
    {
    Display-Error -error "Deleting server failed..." -errorObj $_
    $result = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($result)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $reader.ReadToEnd()
    }
    return $output
}
Function Start-K5Server
{
<#

.SYNOPSIS
Starts an existing K5 VM Server

.DESCRIPTION
This Function starts a K5 VM if it is currently stopped (in which case the function fails). The Function uses the server name and converts it to the unique ID therefore the name must be unique.

This Function uses the server name and converts it to the ID so the name must be unique

.PARAMETER token
Required, a token object for the transaction

.PARAMETER Server
Required, the name of the Server to start (the name must be unique)

.PARAMETER useProxy
Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

.EXAMPLE

#           PS C:\> Start-K5Server -token $token -server MYSERVER -UseProxy
            Server Started


#>
#v1.0 SPA 08/09/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$server = $(Display-Error -error "Please specify a Server name using the -Server parameter"),
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $server)) {break}
    try
    {
        #get the Server ID from the name provided
        $TargetSvr = $token.endpoints["compute"] + "/servers"
        $getSvrId = Invoke-Webrequest2 -token $token -uri $TargetSvr -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $SvrId = (($getSvrId.Content | Convertfrom-Json).servers | where name -eq $Server).id
        
        #test the status of the server
        $Target1 = $token.endpoints["compute"] + "/servers/" + $SvrId
        $getStatus = Invoke-Webrequest2 -token $token -uri $Target1 -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $SvrStatus = ($getStatus.Content | Convertfrom-Json).server
        $Status = $SvrStatus.status
        If ($Status -eq "ACTIVE")
        {WRITE-HOST "Server is already running. Action cancelled"
        break
        }
        If ($Status -eq "BUILD")
        {Write-Host "Server is currently being built. Action cancelled"
        break
        }
        $json = get-K5json StartSvr
        $target=$token.endpoints["compute"] + "/servers/" + $SvrId + "/action"
        $return=Invoke-Webrequest2 -token $token -uri $target -Method POST -headers $token.token -Body $json -ContentType "application/json" -Useproxy $useProxy
        $output=$return | convertfrom-json
    }
    catch
    {
       Display-Error -error "Start server failed..." -errorObj $_
    }
    return Write-Host "Server started"
}
Function Stop-K5Server
{
<#

.SYNOPSIS
Stops a K5 VM Server

.DESCRIPTION
Given the ServerName, this Function determines the Unique ID and then determines if the server is currently Active or not.

If the server is already stopped, the Function fails, otherwise it stops the specified server.

This Function uses the server name and converts it to the ID so the name must be unique

.PARAMETER token
Required, a token object for the transaction

.PARAMETER Server
Required, the name of the Server to stop (the name must be unique)

.PARAMETER useProxy
Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

.EXAMPLE

#           PS C:\> Stop-K5Server -token $token -server MYSERVER -UseProxy
            Server Stopped

#>
#v1.0 SPA 08/09/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$server = $(Display-Error -error "Please specify a Server name using the -Server parameter"),
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $server)) {break}
    try
    {
        #get the Server ID from the name provided
        $TargetSvr = $token.endpoints["compute"] + "/servers"
        $getSvrId = Invoke-Webrequest2 -token $token -uri $TargetSvr -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $SvrId = (($getSvrId.Content | Convertfrom-Json).servers | where name -eq $Server).id
        
        #test the status of the server
        $Target1 = $token.endpoints["compute"] + "/servers/" + $SvrId
        $getStatus = Invoke-Webrequest2 -token $token -uri $Target1 -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $SvrStatus = ($getStatus.Content | Convertfrom-Json).server
        $Status = $SvrStatus.status
        If ($Status -eq "SHUTOFF")
        {WRITE-HOST "Server is already OFF. Action cancelled"
        break
        }
        If ($Status -eq "BUILD")
        {Write-Host "Server is currently being built. Action cancelled"
        break
        }
        $target=$token.endpoints["compute"] + "/servers/" + $SvrId + "/action"
        $json = Get-K5Json StopSvr
        $return=Invoke-Webrequest2 -token $token -uri $target -Method POST -headers $token.token -Body $json -ContentType "application/json" -Useproxy $useProxy
        $output=$return | convertfrom-json
    }
    catch
    {
    Display-Error -error "Start stop failed..." -errorObj $_
    $result = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($result)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $reader.ReadToEnd()
    }
    return Write-Host "Server Stopped"
}
Function Restart-K5Server
{
<#

.SYNOPSIS
Reboots a K5 VM Server

.DESCRIPTION
Reboots an existing K5 VM. Use the optional '-BootType' parameter to specify whether to force a HARD reboot or perfrom a SOFT, graceful reboot. By default, a SOFT reboot is performed if 'BootType' is not specified.

Like 'START' and 'STOP' K5Server, this Function uses the server name and converts it to the ID so the name must be unique

.PARAMETER token
Required, a token object for the transaction

.PARAMETER Server
Required, the name of the Server to restart (must be unique)

.PARAMETER BootType
Optional, state "SOFT" to signal the OS to restart gracefully or "HARD" to force a power cycle. Defaults to "SOFT" if not specified  

.PARAMETER useProxy
Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

.EXAMPLE

#       PS C:\> Restart-K5Server -token $token -boottype soft -server MYSERVER -UseProxy

        Soft reboot intiated

#>
#v1.0 SPA 08/09/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$server = $(Display-Error -error "Please specify a Server name using the -Server parameter"),
        [string]$boottype,
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $server)) {break}
    
    try
    {
        if ($boottype)
            {
                $boottype = $boottype.tostring()
                if ("soft", "hard" -notcontains $boottype)
                    {throw "ERROR $boottype is not a valid BootType; -BootType must equal 'soft' or 'hard'. Leave blank for 'soft'"
                    break
                    }
            }
            else {$boottype = "soft"}
        $output = (Get-Culture).textinfo
        $BT=$output.ToTitleCase($boottype)

        #get the Server ID from the name provided
        $TargetSvr = $token.endpoints["compute"] + "/servers"
        $getSvrId = Invoke-Webrequest2 -token $token -uri $TargetSvr -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $SvrId = (($getSvrId.Content | Convertfrom-Json).servers | where name -eq $Server).id
        
        #test the status of the server
        $Target1 = $token.endpoints["compute"] + "/servers/" + $SvrId
        $getStatus = Invoke-Webrequest2 -token $token -uri $Target1 -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $SvrStatus = ($getStatus.Content | Convertfrom-Json).server
        $Status = $SvrStatus.status
        If ($Status -eq "SHUTOFF")
        {WRITE-HOST "Server is currently OFF. Action cancelled"
        break
        }
        If ($Status -eq "BUILD")
        {Write-Host "Server is currently being built. Action cancelled"
        break
        }
        
        $target=$token.endpoints["compute"] + "/servers/" + $SvrId + "/action"
        $json = Get-K5Json RestartSvr
        $return=Invoke-Webrequest2 -token $token -uri $target -Method POST -headers $token.token -Body $json -ContentType "application/json" -Useproxy $useProxy
    }
    catch
    {
    Display-Error -error "Start stop failed..." -errorObj $_
    $result = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($result)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $reader.ReadToEnd()
    }
    return Write-Host "$BT reboot intiated"
}
Function New-K5Network
{
<#

.SYNOPSIS
Creates a K5 Network

.DESCRIPTION
Given the name and the required Availability Zone, this function creates a new K5 Network. Use New-K5SubNet to then create and attach a subnet to this network.

The function provides the Network UUID in the output.

.PARAMETER token
Required, a token object for the transaction

.PARAMETER NetName
Required, the name of the Network to create

.PARAMETER AZ
Required, the Availability Zone in which to create the new network (e.g. uk-1a, uk-1b, etc.)

.PARAMETER useProxy
Optional, switch parameter to specify that a proxy must be used, if this switch is supplied then the proxyURL in k5env.csv will be used 

.EXAMPLE

#        PS C:\> New-k5Network -token $token -Netname MyLANA -AZ uk-1a -useproxy

Will create a network called 'MyLANA' in the Availability Zone 'uk1a' and provide the following response:

            status            : ACTIVE
            subnets           : {}
            name              : MyLANA
            router:external   : False
            tenant_id         : 3a2ece588b1d412c82ebd7e165dcf172
            admin_state_up    : True
            mtu               : 0
            shared            : False
            id                : 6c23be59-843d-409d-955a-e1aa1c6f5879
            availability_zone : uk-1a

#>
#v1.0 SPA 18/09/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$netname = $(Display-Error -error "Please specify a Network name using the -NetName parameter"),
        [string]$AZ = $(Display-Error -error "Please specify an Availability Zone using the -AZ parameter (e.g. uk-1a, uk1b, etc)"),
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $netname) -or (-not $AZ)) {
    Write-Host "Required parameter missing"
    break}
    try
    {
        $json = Get-K5Json NewNetwork
        $target=$token.endpoints["networking"] + "/v2.0/networks"
        $return=Invoke-Webrequest2 -token $token -uri $target -Method POST -headers $token.token -Body $json -ContentType "application/json" -Useproxy $useProxy
        $output= ($return.content | ConvertFrom-Json).network
        $output=$output
        
    }
    catch
    {
    Display-Error -error "Create network failed..." -errorObj $_
    }
    return $output
}
Function Remove-K5Network
{
<#

.SYNOPSIS
Deletes a K5 Network

.DESCRIPTION
To use this Function use the other functions to remove the associated Router Interface, Router and Subnet (in that order)

.PARAMETER token
Required, a token object for the transaction

.PARAMETER NetName
Optional, the name of the network to be deleted. Use this instead of the Network ID. The function will resolve the name to the ID.

.PARAMETER NetID
Optional, the UUID of the network to be deleted. Use this instead of the Network Name of you know the ID. Use Get-K5Resources with the Network Type to get the Network ID.

.PARAMETER useProxy
Optional

.PARAMETER Force
Optional, used to bypass confirmation of deletion (i.e. no confirmation prompt provided)

.EXAMPLE

#          PS C:\> Remove-K5Network -token $token -netid 0f16cce2-cc2a-4cc0-91ad-b0f6e1831486 -UseProxy

           Delete the network 'MyLANB'? Are you sure? - (Y \ N): y
           Network MyLANB Removed

Uses the Network ID parameter to delete the network.

#          PS C:\> Remove-K5Network -token $token -netname MyLANB -UseProxy

           Delete the network 'MyLANB'? Are you sure? - (Y \ N): y
           Network MyLANB Removed

Uses the Network Name only to delete the network.


#          PS C:\> Remove-K5Network -token $token -netid 0f16cce2-cc2a-4cc0-91ad-b0f6e1831486 -UseProxy
            
           Delete the network 'MyLANB'? Are you sure? - (Y \ N): n
           Delete Cancelled!

Shows a delete request being cancelled (user says 'No' to confirmation request)


#          PS C:\> Remove-K5Network -token $token -netid 0f16cce2-cc2a-4cc0-91ad-b0f6e1831486 -netname MyLANB -UseProxy

           Only one or the other required of 'Network name' or 'Network ID' - not both


#          PS C:\> Remove-K5Network -token $token -UseProxy

           Either the Network Name (-NetName) or Network ID (-NetID) is required


#>
#v1.0 SPA 18/09/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$netid,
        [string]$netname,
        [switch]$UseProxy,
        [switch]$Force
    )
    if (($netname) -and ($NetID))
    {Write-Host "Only one or the other required of 'Network name' or 'Network ID' - not both"
    break}
    if ((-not $netname) -and (-not $netid))
    {Write-Host "Either the Network Name (-NetName) or Network ID (-NetID) is required"
    break} 
    if (-not $token) 
    {Write-Host "Token parameter missing"
    break}
    try
    {

    #Ask for confirmation of deletion
        If ($netname)
        {
        $target1=$token.endpoints["networking"] + "/v2.0/networks"
        $getname=Invoke-Webrequest2 -token $token -uri $target1 -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $networkid=(($getname.content | Convertfrom-Json).networks | where name -eq $netname).id
        $netid = $networkid
        
        }
        If ($netid)
        { 
        $target1=$token.endpoints["networking"] + "/v2.0/networks"
        $getid=Invoke-Webrequest2 -token $token -uri $target1 -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $networkname=(($getid.content | Convertfrom-Json).networks | where id -eq $netid).name
        $netname = $networkname
        
        }
        If ($Force)
        {$choice = "y"}
        Else
        {$choice = ""}
        while ($choice -notmatch "[y|n]")
        {$choice = read-host "Delete the network '$netName'? Are you sure? - (Y \ N)"}
          #If confirmed, delete the network
            if ($choice -eq "y")
        
            {$target=$token.endpoints["networking"] + "/v2.0/networks/" + $netid
            $return=Invoke-Webrequest2 -token $token -uri $target -Method DELETE -headers $token.token -ContentType "application/json" -Useproxy $useProxy
            $output= $netname}
        
            Else
            {$output = Write-Host "Delete Cancelled!"
            break}
    }
    catch
    {
    Display-Error -error "Delete network failed..." -errorObj $_
    <#$result = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($result)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $reader.ReadToEnd()#>
    }
    return Write-Host "Network $netname Removed"

}
Function New-K5Subnet
{
<#

.SYNOPSIS
Creates a K5 TCP/IP Version 4 Network Subnet

.DESCRIPTION
A new K5 network requires a valid TCP/IP Version 4 internal subnet to operate in. This function creates a new subnet using the IP subnet address supplied in the CIDR format (use help with the -Detailed swicth to get more information).
You need to create the Network first and provide the name it with this new subnet.
This function will add the default K5 DNS Servers for the respective region if not specified as a Parameter and automatically assigns the Default Gateway address as the first valid address in the address range provided.

.PARAMETER token
Required, a token object for the transaction

.PARAMETER SubNetName
Required, the name of the SubNet to be created (NB - this is optional in K5 but required in this function)

.PARAMETER NetID
Required, the name of the Network to be associated with this new Subnet

.PARAMETER DNS
Optional, DNS Server addresses (in the format "["nn.nn.nn.nn","nn.nn.nn.nn"]"; if left blank, the default DNS Servers for the specified Availability Zone are used (see the Features Handbook)

.PARAMETER CIDR
Required, the SubNet IP Range as a CIDR ('nn.nn.nn.nn/nn') - e.g. 192.168.0.0/24

.PARAMETER Gateway
Optional, the IP Address to be allocated to the Default Gateway for this subnet

.PARAMETER AZ
Required, the Availability Zone for the new Subnet (NB - whilst optional in K5, it is required in this function to avoid determining the default!)

.PARAMETER useProxy
Optional

.EXAMPLE

#        PS C:\> New-K5Subnet -token $token -subnetname SNTestB -dns `"8.8.8.8`",`"9.9.9.9`" -netID f7d763ab-86cd-4394-a320-65e38fd66415 -cidr 10.1.2.0/24 -gateway 10.1.2.1 -AZ uk-1b -UseProxy

Creates a Subnet 'SNTestB' with DNS Server 8.8.8.8 and 9.9.9.9 (NOTE the `to escape the " marks) in AZ uk-1b


#        PS C:\> New-K5Subnet -token $token -subnetname TestA -netID 2d6de4d4-9539-4717-868c-213b1c9bda4d -cidr 10.1.1.0/24 -gateway 10.1.1.1 -AZ uk-1a -UseProxy

Creates a Subnet 'TestA' in AZ uk-1a. NOTE that this will use the default UK-1A DNS Servers 62.60.39.9 and 62.60.39.10

#>
#v1.0 SPA 18/09/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$subnetname = $(Display-Error -error "Please specify a name for the new Subnet with the -SubNetName parameter"),
        [string]$netID = $(Display-Error -error "Please specify the Network ID for the associated Network using the -NetID parameter"),
        [string]$dns,
        [string]$cidr= $(Display-Error -error "Please specify the Subnet IP Range using the -CIDR parameter"),
        [string]$gateway,
        [string]$AZ= $(Display-Error -error "Please specify the Availability Zone for this subnet using the -AZ parameter"),
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $subnetname)) {Write-host "Required parameter missing"
    break}

    if (-not $dns) 
{
        $DNSSvrs=@{
        "jp-east-1a"="`"133.162.193.9`",`"133.162.193.10`"";
        "jp-east-1b"="`"133.162.201.9`",`"133.162.201.10`"";
        "jp-east-2a"="`"133.162.97.9`",`"133.162.97.10`"";
        "jp-east-2b"="`"133.162.106.9"",`"133.162.106.10`"";
        "jp-west-1a"="`"133.162.161.9"",`"133.162.161.10`"";
        "jp-west-1b"="`"133.162.169.9"",`"133.162.169.10`"";
        "jp-west-2a"="`"133.162.145.9"",`"133.162.145.10`"";
        "jp-west-2b"="`"133.162.153.9"",`"133.162.153.10`"";
        "uk-1a"="`"62.60.39.9"",`"62.60.39.10`"";
        "uk-1b"="`"62.60.42.9"",`"62.60.42.10`"";
        "fi-1a"="`"213.214.162.9"",`"213.214.162.10`"";
        "fi-1b"="`"213.214.165.9"",`"213.214.165.10`"";
        "de-1a"="`"185.149.225.9"",`"185.149.225.10`"";
        "de-1b"="`"185.149.227.9"",`"185.149.227.10`"";
        "es-1a"="`"194.140.26.9"",`"194.140.26.10`"";
        "es-1b"="`"194.140.29.9"",`"194.140.29.10`"";
        "us-1a"="`"148.57.138.9"",`"148.57.138.10`"";
        "us-1b"="`"148.57.142.9"",`"148.57.142.10`""
        }
        If ($DNSSvrs.ContainsKey($AZ))
        {$dns=$DNSSvrs.Get_Item($AZ)}
        Else
        {Write-Host "No DNS servers listed for Availability Zone $AZ; subnet will be created without DNS Servers"}

}
    try
    {
        $json = Get-K5Json NewSubnet
        $target=$token.endpoints["networking"] + "/v2.0/subnets"
        $json
        $target
        $return=Invoke-Webrequest2 -token $token -uri $target -Method POST -headers $token.token -Body $json -ContentType "application/json" -Useproxy $useProxy
        $output= ($return.content | ConvertFrom-Json)
        #$output = $output.subnet
    }
    catch
    {
    Display-Error -error "Create Subnet failed..." -errorObj $_
    <#$result = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($result)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $reader.ReadToEnd()#>
    }
    return $output
}
Function Remove-K5Subnet
{
<#

.SYNOPSIS
Deletes a K5 TCP/IP Version 4 Network Subnet

.DESCRIPTION
Deletes a K5 Internal subnet given its name after prompting for confirmation.

.PARAMETER token
Required, a token object for the transaction

.PARAMETER SubNetName
Required, the name of the SubNet to be deleted. This is converted to the UUID by this function

.PARAMETER useProxy
Optional

.PARAMETER Force
Optional, used to bypass confirmation of deletion (i.e. no confirmation prompt provided)

.EXAMPLE

#       PS C:\> Remove-K5Subnet -token $token -subnetname SNTestB -UseProxy

        Delete the Subnet 'SNTestB'? Are you sure? - (Y \ N): y
        Subnet SNTestB with ID 28e11c82-9815-4649-baf4-a5da5ec4e312 deleted

Successfully deleting the subnet 'SNTestB'


#        PS C:\> Remove-K5Subnet -token $token -subnetname MySubnet -UseProxy

         Delete the Subnet 'MySubnet'? Are you sure? - (Y \ N): n
         Delete Cancelled

Subnet deletion cancelled by user


#        PS C:\> Remove-K5Subnet -token $token -subnetname SNTestB -UseProxy

         Delete the Subnet 'SNTestB'? Are you sure? - (Y \ N): y
        {"NeutronError": {"message": "Unable to complete operation on subnet 28e11c82-9815-4649-baf4-a5da5ec4e312. One or more ports have an IP allocation from this subnet.", "type": "SubnetInUse", "detail": ""}}


This example shows the error when the Subnet is in use (requires the router, gateway port and other connected resources to be deleted first)

#>
#v1.0 SPA 18/09/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$subnetname = $(Display-Error -error "Please specify a name for the new Subnet with the -SubNetName parameter"),
        [switch]$UseProxy,
        [switch]$Force
    )
    if ((-not $token) -or (-not $subnetname)) 
    {Write-host "Required paramter missing"
    break}

    try
    {
    #Get the Subnet ID from the Name
        If ($Force)
        {$choice="y"}
        Else
        {$choice = ""}
        while ($choice -notmatch "[y|n]")
        {$choice = read-host "Delete the Subnet '$subnetname'? Are you sure? - (Y \ N)"}
          #If confirmed, delete the network
            if ($choice -eq "y")         
            {        
            $target1=$token.endpoints["networking"] + "/v2.0/subnets"
            $snid=Invoke-Webrequest2 -token $token -uri $target1 -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
            $getid = (($snid.content | ConvertFrom-Json).subnets | where name -eq $subnetname).id
            $SubnetID = $getid

            $target=$token.endpoints["networking"] + "/v2.0/subnets/" + $SubnetID
            $return=Invoke-Webrequest2 -token $token -uri $target -Method DELETE -headers $token.token -ContentType "application/json" -Useproxy $useProxy
            $output= "Subnet $subnetname with ID $subnetid deleted"
            #$output = $output.subnet
        
            }
            Else
            {Write-Host "Delete Cancelled"
            break}
    }
    catch
    {
    Display-Error -error "Delete Subnet failed..." -errorObj $_
    #$result = $_.Exception.Response.GetResponseStream()
    #$reader = New-Object System.IO.StreamReader($result)
   # $reader.BaseStream.Position = 0
   # $reader.DiscardBufferedData()
   # $reader.ReadToEnd()
    }
    return $output
}
Function New-K5Router
{
<#

.SYNOPSIS
Creates a new K5 Network Router

.DESCRIPTION
This will create a new Router (without interface) in the specified Availability Zone. To make the router useful, you need to add an Interface (use function New-K5UserInterface) on user created Subnet (use function New-K5SubNet)

.PARAMETER token
Required, a token object for the transaction

.PARAMETER RouterName
Required, the name of the Router to create

.PARAMETER AZ
Required, the Availability Zone to create the router in 

.PARAMETER useProxy
Optional

.EXAMPLE

#       PS C:\> New-K5Router -token $token -Routername MyRouter -AZ uk-1a -UseProxy

        Router MyRouter with e8a9e423-845b-4486-989e-78383d2c8eea created

#>
#v1.0 SPA 18/09/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$routername = $(Display-Error -error "Please specify a Router name using the -RouterName parameter"),
        [string]$AZ= $(Display-Error -error "Please specify an Availability Zone name using the -AZ parameter"),
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $routername) -or (-not $AZ)) {Write-Host "Required parameter missing"
    break}
    try
    {
        $json = Get-K5Json NewRouter
        $target=$token.endpoints["networking"] + "/v2.0/routers"
        $return=Invoke-Webrequest2 -token $token -uri $target -Method POST -headers $token.token -Body $json -ContentType "application/json" -Useproxy $useProxy
        $output= ($return.content | ConvertFrom-Json)
        $output = $output.router.id
    }
    catch
    {
     Display-Error -error "Create Router failed..." -errorObj $_
    #$result = $_.Exception.Response.GetResponseStream()
    #$reader = New-Object System.IO.StreamReader($result)
    #$reader.BaseStream.Position = 0
    #$reader.DiscardBufferedData()
    #$reader.ReadToEnd()
    }
    return $output
}
Function Remove-K5Router
{
<#

.SYNOPSIS
Deletes a K5 Network Router

.DESCRIPTION
This will delete a K5 Router given a valid name, after prompting for confirmation. NOTE that the interface must be removed first using 'Remove-K5RouterInterface'

.PARAMETER token
Required, a token object for the transaction

.PARAMETER RouterName
Required, the name of the Router to delete. Note that this fucntion will convert the Router Name to its ID to perform the delete

.PARAMETER useProxy
Optional

.PARAMETER Force
Optional, used to bypass confirmation of deletion (i.e. no confirmation prompt provided)

.EXAMPLE

#       PS C:\> Remove-K5Router -token $token -routername MyRouter -UseProxy

        Delete the Router 'MyRouter'? Are you sure? - (Y \ N): y
        Router MyRouter with ID dc53d4e9-b86e-4c47-8adb-9646fc6806cf deleted


#
        Delete the Router 'MyRouter'? Are you sure? - (Y \ N): y

        {"NeutronError": {"message": "Router dc53d4e9-b86e-4c47-8adb-9646fc6806cf still has ports", "type": "RouterInUse", "detail": ""}}

Shows the error when the Router still has operational ports/interfaces - Use the function 'Remove-K5RouterInterface' first


#>
#v1.0 SPA 18/09/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$routername = $(Display-Error -error "Please specify a Router name using the -Routername parameter"),
        [switch]$UseProxy,
        [switch]$Force
    )
    if ((-not $token) -or (-not $routername)) {Write-Host "Required parameter missing"
    break}
    try
    {

    #Get the Subnet ID from the Name
        If ($Force)
        {$choice = "y"}
        Else
        {$choice = ""}
        while ($choice -notmatch "[y|n]")
        {$choice = read-host "Delete the Router '$routername'? Are you sure? - (Y \ N)"}
          #If confirmed, delete the router
            if ($choice -eq "y")  

            {
        #Get the Router ID from the name
            $target1=$token.endpoints["networking"] + "/v2.0/routers"
            $getid=Invoke-Webrequest2 -token $token -uri $target1 -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
            $RouterId= (($getid.content | ConvertFrom-Json).routers | where name -eq $routername).id
            
        #Remove the router
            $target=$token.endpoints["networking"] + "/v2.0/routers/" + $RouterId
            $return=Invoke-Webrequest2 -token $token -uri $target -Method DELETE -headers $token.token -ContentType "application/json" -Useproxy $useProxy
            $output= "Router $routername with ID $routerid deleted"
            }
            Else
            {Write-Host "Delete Cancelled"
            break}

    }
    catch
    {
     Display-Error -error "Delete Router failed..." -errorObj $_
   # $result = $_.Exception.Response.GetResponseStream()
   # $reader = New-Object System.IO.StreamReader($result)
    #$reader.BaseStream.Position = 0
    #$reader.DiscardBufferedData()
    #$reader.ReadToEnd()
    }
    return Write-Host $output
}
Function New-K5RouterInterface
{
<#

.SYNOPSIS
Creates a Network Interface on a specified K5 Router

.DESCRIPTION
Having created an internal network and subnet and created a router, the router needs to be connected to that network and obtain its internal Gateway address.

This function adds an internal interface to the router and connects it to the internal network and asigns the Default Gateway address.

Use "Update-K5Router" after this to connect the router to an external K5 network and begin routing.

.PARAMETER token
Required, a token object for the transaction

.PARAMETER RouterID
Required, the UUID of the Router to add the interface to

.PARAMETER SubNetID
Required, the UUID of the SubNet to connect the router interface to

.PARAMETER useProxy
Optional


.EXAMPLE

#       PS C:\> Add-K5RouterInterface -token $token -subnetid 28e11c82-9815-4649-baf4-a5da5ec4e312 -routerid dc53d4e9-b86e-4c47-8adb-9646fc6806cf -UseProxy

        subnet_id         : 28e11c82-9815-4649-baf4-a5da5ec4e312
        tenant_id         : 3a2ece588b1d412c82ebd7e165dcf172
        subnet_ids        : {28e11c82-9815-4649-baf4-a5da5ec4e312}
        port_id           : 7336739c-64f5-4a30-91de-0d3252dae39f
        id                : dc53d4e9-b86e-4c47-8adb-9646fc6806cf
        availability_zone : uk-1a

Shows a router interface being added to the Router (MyRouter id) on Subnet (MySubnet id). The successful output shows the interface ID among others

#>
#v1.0 SPA 18/09/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$subnetid = $(Display-Error -error "Please specify the Subnet ID using the -SubnetID parameter"),
        [string]$routerid= $(Display-Error -error "Please specify the Router ID name using the -RouterID parameter"),
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $subnetid) -or (-not $routerid)) {break}
    try
    {
        $json = Get-K5Json NewRouterIF
        $target=$token.endpoints["networking"] + "/v2.0/routers/" + $routerid + "/add_router_interface"
        $return=Invoke-Webrequest2 -token $token -uri $target -Method PUT -headers $token.token -Body $json -ContentType "application/json" -Useproxy $useProxy
        $output= ($return.content | ConvertFrom-Json)
        #$output = $output.subnet
    }
    catch
    {
     Display-Error -error "Create Network Interface failed..." -errorObj $_
    #$result = $_.Exception.Response.GetResponseStream()
    #$reader = New-Object System.IO.StreamReader($result)
    #$reader.BaseStream.Position = 0
    #$reader.DiscardBufferedData()
    #$reader.ReadToEnd()
    }
    return $output
}
Function Remove-K5RouterInterface
{
<#

.SYNOPSIS
Deletes a Network Interface on a specified K5 Router

.PARAMETER token
Required, a token object for the transaction

.PARAMETER RouterName
Required, the Name of the Router to delete the interface from

.PARAMETER SubNetName
Required, the name of the Internal SubNet associated with the router interface

.PARAMETER useProxy
Optional

.PARAMETER Force
Optional, used to bypass confirmation of deletion (i.e. no confirmation prompt provided)

.EXAMPLE

#       PS C:\> Remove-K5RouterInterface -token $token -subnetname MySubnet -routername MyRouter -UseProxy
    
        Delete the Router Interface on 'MyRouter'? Are you sure? - (Y \ N): y
        Router Interface removed on router MyRouter


Shows a router interface being deleted from the Router 'MyRouter' on Subnet 'MySubnet'. 

#>
#v1.0 SPA 18/09/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$subnetname = $(Display-Error -error "Please specify the Subnet name using the -SubnetName parameter"),
        [string]$routername= $(Display-Error -error "Please specify the Router name using the -RouterName parameter"),
        [switch]$UseProxy,
        [switch]$Force

    )
    if ((-not $token) -or (-not $subnetname) -or (-not $routername)) {break}
    try
    {
    #Ask for confirmation
        If ($Force)
        {$choice="y"}
        Else
        {$choice = ""}
        while ($choice -notmatch "[y|n]")
        {$choice = read-host "Delete the Router Interface on '$routername'? Are you sure? - (Y \ N)"}
          #If confirmed, delete the router
            if ($choice -eq "y") 
        
        {
        #Get the Router ID from the name
        $t1=$token.endpoints["networking"] + "/v2.0/routers"
        $rtr=Invoke-Webrequest2 -token $token -uri $t1 -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $routerid = (($rtr.content | ConvertFrom-Json).routers | where name -eq $routername).id
        #Get the Subnet ID form the name
        $t2=$token.endpoints["networking"] + "/v2.0/subnets"
        $sn=Invoke-Webrequest2 -token $token -uri $t2 -Method GET -headers $token.token -ContentType "application/json" -Useproxy $useProxy
        $subnetid = (($sn.content | ConvertFrom-Json).subnets | where name -eq $subnetname).id

        #Now delete the interface
        $json = Get-K5Json NewRouterIF
        $target=$token.endpoints["networking"] + "/v2.0/routers/" + $routerid + "/remove_router_interface"
        $return=Invoke-Webrequest2 -token $token -uri $target -Method PUT -headers $token.token -Body $json -ContentType "application/json" -Useproxy $useProxy
        $output= "Router Interface removed on router $routername"
        #$output = $output.subnet
        }
        Else {Write-Host "Delete Cancelled"
        break}
    }
    catch
    {
     Display-Error -error "Delete Router Interface failed..." -errorObj $_
    #$result = $_.Exception.Response.GetResponseStream()
    #$reader = New-Object System.IO.StreamReader($result)
    #$reader.BaseStream.Position = 0
    #$reader.DiscardBufferedData()
    #$reader.ReadToEnd()
    }
    return $output

}
Function Update-K5Router
{
<#

.SYNOPSIS
Updates a K5 Router with the external gateway information to enable routing to work

.DESCRIPTION
Used after the Router has been created (New-K5Router) and the router given an interface (New-K5RouterInterface) on a valid subnet. This assigns the gateway address to the specified router interface.

This function uses the Network name and Router Name but converts them to the relevant ID to complete the action.

.PARAMETER token
Required, a token object for the transaction

.PARAMETER Router
Required, the name of the Router for which it will act as a gateway

.PARAMETER ExtNetwork
Required, the name of the EXTERNAL Network that the internal network is required to route to

.PARAMETER useProxy
Optional

.EXAMPLE


#       PS C:\> Update-K5Router -token $token -router MyRouter -ExtNetwork inf_az1_ext-net01 -useProxy


        status                : ACTIVE
        external_gateway_info : @{network_id=0a23d6f7-2f94-4cf3-aebb-587b29ac9538; enable_snat=True; external_fixed_ips=System.Object[]}
        name                  : MyRouter
        admin_state_up        : True
        tenant_id             : 3a2ece588b1d412c82ebd7e165dcf172
        routes                : {}
        id                    : b42f180e-ca82-4f39-aeef-e0dfe2740f01
        availability_zone     : uk-1a

This updates the Router "MyRouter" so that it routes to the External K5 Network "inf_az1_ext-net01"


#>
#v1.0 SPA 18/09/2017
param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$router = $(Display-Error -error "Please specify the Router name using the -Router parameter"),
        [string]$extnetwork= $(Display-Error -error "Please specify the External Network name using the -ExtNetwork parameter"),
        [switch]$useProxy
    )
    if ((-not $token) -or (-not $router) -or (-not $extnetwork)) {break}
    try
    {
    #Get the Network ID of the External Network provided by the Gateway Parameter
        $target=$token.endpoints["networking"] + "/v2.0/networks"
        $GWNet=Invoke-Webrequest2 -token $token -uri $target -Method GET -Headers $token.token -ContentType "application/json" -UseProxy $useProxy
        $extNet = (($GWNet.Content | ConvertFrom-Json).networks | where name -eq $extnetwork).id
        

    #Get the router ID from the router name supplied in the function
        $target1=$token.endpoints["networking"] + "/v2.0/routers"
        $RTRID=Invoke-Webrequest2 -token $token -uri $target1 -Method GET -Headers $token.token -ContentType "application/json" -UseProxy $useProxy
        $routerid= (($RTRID.Content | ConvertFrom-Json).routers | where name -eq $router).id
        
        
    <#Having got the Router ID, determine if the current gateway is NULL
        $target2=$token.endpoints["networking"] + "/v2.0/routers/" + $routerid
        $return3=Invoke-Webrequest2 -token $token -uri $target2 -Method GET -Headers $token.token -ContentType "application/json" -UseProxy $useProxy
        $myRouter= ($return3.Content | ConvertFrom-Json).router.external_gateway_info#>

    #set the router external gateway to the external network (Network ID) in the Gateway parameter
        $gateway=$extNet
        $json = Get-K5Json RouterGateway
        $target=$token.endpoints["networking"] + "/v2.0/routers/" + $routerid
        $return=Invoke-Webrequest2 -token $token -uri $target -Method PUT -headers $token.token -Body $json -ContentType "application/json" -Useproxy $useProxy
        $output= ($return.content | ConvertFrom-Json).router

    }
    catch
    {
     #Display-Error -error "Create server failed..." -errorObj $_
    $result = $_.Exception.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($result)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $reader.ReadToEnd()
    }
    return $output
}


