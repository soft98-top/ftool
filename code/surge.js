let surge_version_payload = {
    "x86_64":{
        "5.3.0":0x19546a,
        "5.4.3":0x1994ae,
        "4.11.2":0x165463
    },
    "arm64":{
        "4.11.2":0x127100
    }
}
let retval_to_1 = "retval.replace(ptr(0x1));";
let version = getVersion();
let arch = getArch();
send(arch + ":" + version)
hookMethodByOffset("Surge",surge_version_payload[arch][version],{"onLeave":retval_to_1});