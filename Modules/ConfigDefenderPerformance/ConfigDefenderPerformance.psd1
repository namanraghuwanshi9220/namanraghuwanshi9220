@{
    GUID = 'A51E6D9E-BC14-41A7-98A8-888195641250'
    Author="Microsoft Corporation"
    CompanyName="Microsoft Corporation"
    Copyright="Copyright (C) Microsoft Corporation. All rights reserved."
    ModuleVersion = '1.0'
    NestedModules = @('MSFT_MpPerformanceRecording.psm1')

    FormatsToProcess = @('MSFT_MpPerformanceReport.Format.ps1xml')

    CompatiblePSEditions = @('Desktop', 'Core')

    FunctionsToExport = @( 'New-MpPerformanceRecording',
                           'Get-MpPerformanceReport'
                           )
    HelpInfoUri="http://go.microsoft.com/fwlink/?linkid=390762"
    PowerShellVersion = '5.1'
}

# SIG # Begin signature block
# MIIlpgYJKoZIhvcNAQcCoIIllzCCJZMCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC5QoGq9EV41ZN5
# fnwNlxKx8aIBP8W7y/AxkQ4SrJmPcKCCC2IwggTvMIID16ADAgECAhMzAAAK69Nl
# RIMWPjjtAAAAAArrMA0GCSqGSIb3DQEBCwUAMHkxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBD
# QSAyMDEwMB4XDTIzMTAxOTE5MTgwMloXDTI0MTAxNjE5MTgwMlowcDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEaMBgGA1UEAxMRTWljcm9zb2Z0
# IFdpbmRvd3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfg+TEc3bT
# Vvq+rfw2TA/Aluhr9MvjyW4v2sVY1+wdq98kJogwk5wRwMEPNKacaRJn02l8VCT5
# eblNMpXt3iD7AcYN+cSnvC4rBDCNKAJAf1ND9AYU9kpP3eKKrxjkbNq5I5uxrIRW
# AP2K3gqGsN8peSb+7/BCINSMrmJ7Tx46PXz8asIJY3TEmq4x13zC5uXtIIb1s/d1
# PWrE9KDPyz16VZQx+ZlNEnFVXH6Cg2gw7AJMQLUHJgeLfLcBilLd/P+2j04e7dgD
# s6fc0Wrw+Bz5EA/kV77PxHLEt7apceKqp5+dNMo1unzlZuMIh5+A6HA7aXbdF9KX
# ujJ6b2MlurVnAgMBAAGjggF3MIIBczAfBgNVHSUEGDAWBgorBgEEAYI3CgMGBggr
# BgEFBQcDAzAdBgNVHQ4EFgQUU6kklw2HQNa4/ec1p2tW744uJekwVAYDVR0RBE0w
# S6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGlt
# aXRlZDEWMBQGA1UEBRMNMjMwMDI4KzUwMTcwNTAfBgNVHSMEGDAWgBTRT6mKBwjO
# 9CQYmOUA//PWeR03vDBTBgNVHR8ETDBKMEigRqBEhkJodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNXaW5QQ0FfMjAxMC0wNy0wNi5j
# cmwwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzAChjtodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpL2NlcnRzL01pY1dpblBDQV8yMDEwLTA3LTA2LmNydDAMBgNV
# HRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQBks51pE8oGEEiS12JhhlAAD/Hf
# E6sdGt6b37sp62b9mymV/X3pl4YjPxzeckToiB4SBLLCuG6PCFWBWvKF3QZV7p4L
# fClCVjXz5SRXHzgZlXnEReG7r4GMXZ9i06zcSWcy/rFEINTZtPCwLYMNTEIpcW+t
# ojVpI6X4FRV5YjfFirE4qmmLYyTQioPYJO5/n2/Xz/BcNj2GFvGycjAtuITmvlPH
# g/ZTaTas8PD5loz8YKngKl/DvfTWEHDyYAdmNZcNRP2BuKf3kksHN20z6Lf/JCK1
# et2f5zMarFELgr12wrdI/8z4+hleNPf9cqU36jrEFauG+XaucS5UlnGp043TMIIG
# azCCBFOgAwIBAgIKYQxqGQAAAAAABDANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNzA2MjA0MDIz
# WhcNMjUwNzA2MjA1MDIzWjB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgV2luZG93cyBQQ0EgMjAxMDCCASIw
# DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMB5uzqx8A+EuK1kKnUWc9C7B/Y+
# DZ0U5LGfwciUsDh8H9AzVfW6I2b1LihIU8cWg7r1Uax+rOAmfw90/FmV3MnGovdS
# cFosHZSrGb+vlX2vZqFvm2JubUu8LzVs3qRqY1pf+/MNTWHMCn4x62wK0E2XD/1/
# OEbmisdzaXZVaZZM5NjwNOu6sR/OKX7ET50TFasTG3JYYlZsioGjZHeYRmUpnYMU
# pUwIoIPXIx/zX99vLM/aFtgOcgQo2Gs++BOxfKIXeU9+3DrknXAna7/b/B7HB9jA
# vguTHijgc23SVOkoTL9rXZ//XTMSN5UlYTRqQst8nTq7iFnho0JtOlBbSNECAwEA
# AaOCAeMwggHfMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTRT6mKBwjO9CQY
# mOUA//PWeR03vDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMC
# AYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvX
# zpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20v
# cGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYI
# KwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBnQYDVR0g
# BIGVMIGSMIGPBgkrBgEEAYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9QS0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUH
# AgIwNB4yIB0ATABlAGcAYQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBl
# AG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAC5Bpoa1Bm/wgIX6O8oX6cn65DnC
# lHDDZJTD2FamkI7+5Jr0bfVvjlONWqjzrttGbL5/HVRWGzwdccRRFVR+v+6llUIz
# /Q2QJCTj+dyWyvy4rL/0wjlWuLvtc7MX3X6GUCOLViTKu6YdmocvJ4XnobYKnA0b
# jPMAYkG6SHSHgv1QyfSHKcMDqivfGil56BIkmobt0C7TQIH1B18zBlRdQLX3sWL9
# TUj3bkFHUhy7G8JXOqiZVpPUxt4mqGB1hrvsYqbwHQRF3z6nhNFbRCNjJTZ3b65b
# 3CLVFCNqQX/QQqbb7yV7BOPSljdiBq/4Gw+Oszmau4n1NQblpFvDjJ43X1PRozf9
# pE/oGw5rduS4j7DC6v119yxBt5yj4R4F/peSy39ZA22oTo1OgBfU1XL2VuRIn6Mj
# ugagwI7RiE+TIPJwX9hrcqMgSfx3DF3Fx+ECDzhCEA7bAq6aNx1QgCkepKfZxpol
# Vf1Ayq1kEOgx+RJUeRryDtjWqx4z/gLnJm1hSY/xJcKLdJnf+ZMakBzu3ZQzDkJQ
# 239Q+J9iguymghZ8ZrzsmbDBWF2osJphFJHRmS9J5D6Bmdbm78rj/T7u7AmGAwcN
# Gw186/RayZXPhxIKXezFApLNBZlyyn3xKhAYOOQxoyi05kzFUqOcasd9wHEJBA1w
# 3gI/h+5WoezrtUyFMYIZmjCCGZYCAQEwgZAweTELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEjMCEGA1UEAxMaTWljcm9zb2Z0IFdpbmRvd3MgUENB
# IDIwMTACEzMAAArr02VEgxY+OO0AAAAACuswDQYJYIZIAWUDBAIBBQCgga4wGQYJ
# KoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQB
# gjcCARUwLwYJKoZIhvcNAQkEMSIEICjaAYW6dpF96OECCa1j0HmEWEEdofGluuKS
# KwAnvISeMEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEa
# gBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEAaxgs
# 9GkngpovGZ++THpqnZRiAcdPPw0wrkmXHC/WHOqLT1FEVw3B3NMjc818wWbLlYtb
# f3geto2AIEcVBIq3DvZA0nm1OId6pmsER3FzA314dSjj2ln54h5T0r46eX5996i9
# Tm/vT4whBKAfGq98C9cGcCUXqpD8EhB+QjbHfKofqZLSAhtJeo6N8s/mc0MHNSvp
# 2Abh6w1qRt0wRjpByyanYrNSBrpqATFTiq5GQgGRi2/MtB2t1UpMjqw+N2YnBZqR
# laeoHW84Lm2fgeYgm0qdHmsfYDjYYlU+PmPp9Omb2cOIGqhtl/f3zPTJVdzcFDaM
# qnnAonXp99i6JFu3TKGCFykwghclBgorBgEEAYI3AwMBMYIXFTCCFxEGCSqGSIb3
# DQEHAqCCFwIwghb+AgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsqhkiG9w0BCRAB
# BKCCAUgEggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCCs
# NQqhRClUZDXHBEqXRdiBxl3jjjYSt87orYc9z50r3wIGZjOicibjGBMyMDI0MDUx
# MTAxMTM0NC40MDFaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVy
# YXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjJBRDQtNEI5
# Mi1GQTAxMSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIR
# eDCCBycwggUPoAMCAQICEzMAAAHenkielp8oRD0AAQAAAd4wDQYJKoZIhvcNAQEL
# BQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjMxMDEyMTkwNzEy
# WhcNMjUwMTEwMTkwNzEyWjCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBM
# aW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoyQUQ0LTRCOTItRkEwMTEl
# MCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBALSB9ByF9UIDhA6xFrOniw/xsDl8sSi9rOCO
# XSSO4VMQjnNGAo5VHx0iijMEMH9LY2SUIBkVQS0Ml6kR+TagkUPbaEpwjhQ1mprh
# RgJT/jlSnic42VDAo0en4JI6xnXoAoWoKySY8/ROIKdpphgI7OJb4XHk1P3sX2pN
# Z32LDY1ktchK1/hWyPlblaXAHRu0E3ynvwrS8/bcorANO6DjuysyS9zUmr+w3H3A
# EvSgs2ReuLj2pkBcfW1UPCFudLd7IPZ2RC4odQcEPnY12jypYPnS6yZAs0pLpq0K
# RFUyB1x6x6OU73sudiHON16mE0l6LLT9OmGo0S94Bxg3N/3aE6fUbnVoemVc7FkF
# Lum8KkZcbQ7cOHSAWGJxdCvo5OtUtRdSqf85FklCXIIkg4sm7nM9TktUVfO0kp6k
# x7mysgD0Qrxx6/5oaqnwOTWLNzK+BCi1G7nUD1pteuXvQp8fE1KpTjnG/1OJeehw
# KNNPjGt98V0BmogZTe3SxBkOeOQyLA++5Hyg/L68pe+DrZoZPXJaGU/iBiFmL+ul
# /Oi3d83zLAHlHQmH/VGNBfRwP+ixvqhyk/EebwuXVJY+rTyfbRfuh9n0AaMhhNxx
# g6tGKyZS4EAEiDxrF9mAZEy8e8rf6dlKIX5d3aQLo9fDda1ZTOw+XAcAvj2/N3DL
# VGZlHnHlAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUazAmbxseaapgdxzK8Os+naPQ
# EsgwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBU
# oFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9z
# b2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEB
# BGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5j
# cnQwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8B
# Af8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBAOKUwHsXDacGOvUIgs5HDgPs0LZ1
# qyHS6C6wfKlLaD36tZfbWt1x+GMiazSuy+GsxiVHzkhMW+FqK8gruLQWN/sOCX+f
# GUgT9LT21cRIpcZj4/ZFIvwtkBcsCz1XEUsXYOSJUPitY7E8bbldmmhYZ29p+XQp
# IcsG/q+YjkqBW9mw0ru1MfxMTQs9MTDiD28gAVGrPA3NykiSChvdqS7VX+/LcEz9
# Ubzto/w28WA8HOCHqBTbDRHmiP7MIj+SQmI9VIayYsIGRjvelmNa0OvbU9CJSz/N
# fMEgf2NHMZUYW8KqWEjIjPfHIKxWlNMYhuWfWRSHZCKyIANA0aJL4soHQtzzZ2Mn
# NfjYY851wHYjGgwUj/hlLRgQO5S30Zx78GqBKfylp25aOWJ/qPhC+DXM2gXajIXb
# l+jpGcVANwtFFujCJRdZbeH1R+Q41FjgBg4m3OTFDGot5DSuVkQgjku7pOVPtldE
# 46QlDg/2WhPpTQxXH64sP1GfkAwUtt6rrZM/PCwRG6girYmnTRLLsicBhoYLh+EE
# FjVviXAGTk6pnu8jx/4WPWu0jsz7yFzg82/FMqCk9wK3LvyLAyDHN+FxbHAxtgwa
# d7oLQPM0WGERdB1umPCIiYsSf/j79EqHdoNwQYROVm+ZX10RX3n6bRmAnskeNhi0
# wnVaeVogLMdGD+nqMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTAN
# BgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9y
# aXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDi
# vbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5G
# awcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUm
# ZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjks
# UZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvr
# g0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31B
# mkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PR
# c6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRR
# RuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSR
# lJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflS
# xIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHd
# MIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSa
# voKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYD
# VR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjR
# PZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNy
# bDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0G
# CSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHix
# BpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjY
# Ni6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe5
# 3Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BU
# hUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QM
# vOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1A
# PMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsN
# n6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFs
# c/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue1
# 0CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6g
# MTN9vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm
# 8qGCAtQwggI9AgEBMIIBAKGB2KSB1TCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0
# aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjoyQUQ0LTRCOTIt
# RkEwMTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEB
# MAcGBSsOAwIaAxUAaKBSisy4y86pl8Xy22CJZExE2vOggYMwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOnoq+MwIhgP
# MjAyNDA1MTAyMjIxMjNaGA8yMDI0MDUxMTIyMjEyM1owdDA6BgorBgEEAYRZCgQB
# MSwwKjAKAgUA6eir4wIBADAHAgEAAgIF5TAHAgEAAgIR1TAKAgUA6en9YwIBADA2
# BgorBgEEAYRZCgQCMSgwJjAMBgorBgEEAYRZCgMCoAowCAIBAAIDB6EgoQowCAIB
# AAIDAYagMA0GCSqGSIb3DQEBBQUAA4GBAHx58IHkhYwCz2BUNvLUDweOhrYdFE/O
# xcHmHrDs9L98iYaqyACE+4aecC5inCiA4rkFp0O56iPA3NoRgdJCB4+5z1nYJLaL
# R3Jwp5ZjYuL6gotdKcFpk2ReHzNfZQbCgIW1yBNauOnXjvt3XMmNslQH5zPfb4Co
# IG0CbZOycLbZMYIEDTCCBAkCAQEwgZMwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENB
# IDIwMTACEzMAAAHenkielp8oRD0AAQAAAd4wDQYJYIZIAWUDBAIBBQCgggFKMBoG
# CSqGSIb3DQEJAzENBgsqhkiG9w0BCRABBDAvBgkqhkiG9w0BCQQxIgQgXXBNh8pz
# 13+3lzffScapF7RuRG2HcXMXFzfJKEWZ/aMwgfoGCyqGSIb3DQEJEAIvMYHqMIHn
# MIHkMIG9BCCOPiOfDcFeEBBJAn/mC3MgrT5w/U2z81LYD44Hc34dezCBmDCBgKR+
# MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMT
# HU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAB3p5InpafKEQ9AAEA
# AAHeMCIEIGDQdTheQEk13kC99wfNZ/c8APX+lnzJQTtCWCHxp/kiMA0GCSqGSIb3
# DQEBCwUABIICAF5npsTJPD8G4a7Z7XL+o3SO3Rfn4sVVPvrbW5WgegMo2Z6UJhyF
# cbYq75huwqjl71KuXX8qPVJpzL6eCi6i7PUnBapdziNwGO/DuHD+gJiRDdn4AZNN
# ixAOGxu0z3Fkz1e8IVF9H6vbfmLtUZNlX1gWt/Cinue8YbNq1cc4zJPZi4OD/OBe
# iimaMsvJQxGHprMa1xt63EB9Ts16Uz5nTRJwlJ9plDPBI36g2bR8R9010SQjmCVQ
# 6rX3uEr75xL6U4xiTsvtYLKyaQKr4ZCN4f0JHeZRoAippsXZsoAScZXHO3sXZrci
# GuvymP7iXS6j699/DiHbOBC8ysMXB1o0cNWZNhYKtNzgfWlSa37zVzPId2oO/3sD
# ISzG3SRRCMyUwMO9fvFsx1ELTXq/l+evjH9Jzh25sG5C+qMYl3YJZx4U/pE8o5rF
# +ZtLy6G/zuogRjnlIOFcuAhfaGAs1h41rBUUHQwDN5VM+EV9xJw6CWqtIFrpH61R
# WvByQoseyM01dmHFtubxuNvUDgbmRgE0FjDk7LntynR5ASbAAXmYxWz7/QViZ6CU
# kfEIrw84016yfzPPrsr7okJUwrtexZ4DXff55Tuxvqr3U4wmEbsEB7VsbfPevoWJ
# EzLTXia5fM3AG+3o3y662DfoEZij9OuAt3cY+58Hk0M9eG+M1iHf2ZnO
# SIG # End signature block