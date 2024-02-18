let surge_version_payload = {
    "5.3.0":0x19546a,
    "5.4.3":0x1994ae,
    "4.11.2":0x165463
}
let retval_to_1 = "retval.replace(ptr(0x1));";
let version = getVersion();
send(version)
hookMethodByOffset("Surge",surge_version_payload[version],{"onLeave":retval_to_1});