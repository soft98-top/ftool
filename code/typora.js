let retval_to_1 = "retval.replace(ptr(0x1));";
let typora_crack = function () {
    let json_data = {
        "code":0,
        "retry":true,
        "msg":{
            "email":"admin@admin.com",
            "license":"XXXXXX-XXXXXX-XXXXXX-XXXXXX"
        }
    }
    let crack_data = jsonToObjc(json_data);
    retval.replace(crack_data);
}
hookMethod("LicenseManager","- verifySig:",{"onLeave":retval_to_1});
hookMethod("LicenseManager","- validateEmail:",{"onLeave":retval_to_1});
hookMethod("LicenseManager","- quickValidateLicense:",{"onLeave":retval_to_1});
hookMethod("Utils","- jsonStringToObject:",{"onLeave":funcToString(typora_crack)});