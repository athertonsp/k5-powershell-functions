function Get-K5JSON
{
    param ([string]$k5json)

$token_global = @"
{
  "auth": {
    "identity": {
      "password": {
        "user": {
          "contract_number": '$contract',
          "name": '$user',
          "password": '$password'
        }
      }
    }
  }
}
"@

$token_unscoped = @"
{
  "auth": {
    "identity": {
      "methods": [
        "password"
      ],
      "password": {
        "user": {
          "domain": {
            "name": '$contract'
          },
          "name": '$user',
          "password": '$password'
        }
      }
    }
  }
}
"@

$token_scoped = @"
{
  "auth": {
    "identity": {
      "methods": [
        "password"
      ],
      "password": {
        "user": {
          "domain": {
            "name": '$contract'
          },
          "name": '$user',
          "password": '$password'
        }
      }
    },
    "scope": {
      "project": {
        "id": '$projectid'
      }
    }
  }
}
"@

$network = @"
{
  "network": {
    "name": '$name',
    "admin_state_up": '$admin_state_up',
    "availability_zone": '$availability_zone'
  }
}
"@

$subnet = @"
{
  "subnet": {
    "name": '$name',
    "network_id": '$network_id',
    "ip_version": 4,
    "cidr": '$cidr',
    "availability_zone": '$availability_zone'
  }
}
"@

$network_connector = @()
 $network_connector += @"
{
  "network_connector": {
    "name": '$name'
  }
}
"@
 $network_connector += @"
{
  "network_connector": {
    "blah": '$name'
  }
}
"@

$vnc_console = @"
{
  "os-getVNCConsole": {
    "type": "novnc"
  }
}
"@

$tty_console = @"
{
  "os-getConsoleOutput": {
    "length": $lines
  }
}
"@

$vpnservice = @"
{
  "vpnservice": {
    "subnet_id": '$subnet_id',
    "router_id": '$router_id',
    "name": '$name',
    "admin_state_up": '$admin_state_up',
    "description": '$description',
    "availability_zone": '$availability_zone'
  }
}
"@
#Following added by Steve Atherton 31 August for additional functions
$cloneToImage = @"
{
  "os-volume_upload_image": {
    "container_format": '$cformat',
    "disk_format": '$dformat',
    "image_name": '$imageName',
    "force": $F
  }
}
"@
$shareToProject = @"
{
  "member":'$MemberID'
}
"@
$confirmFromProject = @"
{
  "status": "accepted"
}
"@

$RegObjStore = @"
{
  "name": '$imageName',
  "location": '$imageLocn',
  "min_ram": $minMem,
  "min_disk": $minDisk,
  "os_type": '$OSType'
}
"@
$NewServer = @"
{
  "server": {
    "name": '$server',
    "flavorRef": '$flavor',
    "imageRef": "",
    "key_name": '$keyPair',
    "availability_zone": '$AZ',
    "networks": [{
       "uuid": '$netUUID'}],
    "security_groups": [{
       "name": '$securityGroup'
      }],
    "block_device_mapping_v2": [{
        "uuid": '$image',
        "device_name": '$device',
        "source_type": '$source',
        "destination_type": "volume",
        "volume_size": '$disk',
        "boot_index": "0",
        "delete_on_termination": '$DelOnTerminate'
       }]
  }   
}
"@ 
$NewNetwork = @"
{
  "network": {
    "name": '$netname',
    "admin_state_up": true,
    "availability_zone": '$AZ'
  }
} 
"@
$NewSubnet = @"
{
  "subnet": {
    "name": '$subnetname',
    "network_id": '$netID',
    "cidr": '$cidr',
    "dns_nameservers": [$dns],
    "ip_version": 4,
    "gateway_ip": '$gateway',
    "availability_zone": '$AZ'
  }
}
"@ 
$NewRouter = @"
{
  "router": {
    "name": '$routername',
    "admin_state_up": true,
    "availability_zone": '$AZ'
  }
} 
"@
$NewRouterIF = @"
{
  "subnet_id": '$subnetid'
} 
"@
$RouterGateway = @"
{
  "router": {
    "external_gateway_info": {
        "network_id": '$gateway'
        }
    }
} 
"@
$StopSvr = @"
{
"os-stop": null
} 
"@
$StartSvr = @"
{
"os-start": null
} 
"@
$RestartSvr = @"
{
"reboot": {
    "type": '$boottype'
    }
} 
"@

Set-Variable -name json -Value ((Get-Variable -name $k5json).Value -replace "'",'"')
return $json
}