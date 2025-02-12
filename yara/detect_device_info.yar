rule DetectDeviceInfo
{
    meta:
        description = "Detects device information like model name"
        author = "Park"
        date = "2025-01-24"
    strings:
        $modelname = "modelname"
        $deviceinfo = "deviceinfo"
        $serialnumber = "serialnumber"
        $manufacturer = "manufacturer"
        $firmware = "firmware"
    condition:
        any of them
}
