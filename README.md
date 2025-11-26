# NGSIEM-CQL-Queries
CQL queries to aid in analyzing log data in Falcon LogScale. Nothing serious, just some queries that I've found useful and would like to share with other professionals.

### USB Device Allowlisting 
This query shows USB activity related to allowlisted devices or policies in Falcon LogScale.  

```
in(#event_simpleName, values=[DcUsbDeviceWhitelisted, DcUsbDevicePolicyViolation, DcUsbDeviceConnected])
| table(@timestamp, DcPolicyAction, DcPolicyFlags, DcPolicyMassStorageBlockPermissions, DeviceProduct,
        DeviceUserAuthenticationId, ComputerName, aid)
| case {
        DcPolicyAction = "0"  | DcPolicyAction := "ALLOW" ;
        DcPolicyAction = "1"  | DcPolicyAction := "BLOCK" ;
        DcPolicyAction = "2"  | DcPolicyAction := "MASSSTORAGE" ;
        * ;
    }

| case {
        DcPolicyFlags = "0"   | DcPolicyFlags := "NONE" ;
        DcPolicyFlags = "1"   | DcPolicyFlags := "SHOW_IN_UI" ;
        DcPolicyFlags = "2"   | DcPolicyFlags := "INVASIVE_BLOCK" ;
        DcPolicyFlags = "4"   | DcPolicyFlags := "REPORT_ONLY" ;
        DcPolicyFlags = "8"   | DcPolicyFlags := "MTP_PTP_RULE" ;
        DcPolicyFlags = "16"  | DcPolicyFlags := "ALLOWLIST_RULE" ;
        DcPolicyFlags = "32"  | DcPolicyFlags := "ALLOWLIST_DISABLE_VIRTUAL" ;
        DcPolicyFlags = "64"  | DcPolicyFlags := "FEATURE_DISABLED" ;
        * ;
    }

| case {
        DcPolicyMassStorageBlockPermissions = "0" | DcPolicyMassStorageBlockPermissions := "NONE" ;
        DcPolicyMassStorageBlockPermissions = "1" | DcPolicyMassStorageBlockPermissions := "READ" ;
        DcPolicyMassStorageBlockPermissions = "2" | DcPolicyMassStorageBlockPermissions := "WRITE" ;
        DcPolicyMassStorageBlockPermissions = "4" | DcPolicyMassStorageBlockPermissions := "EXECUTE" ;
        * ;
    }

| DcPolicyFlags = "ALLOWLIST_RULE"
```
