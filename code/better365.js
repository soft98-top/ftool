let func_better365 = function () {
    let json_data = {
        "status":0,
        "receipt":{
          "in_app":[
            {
                "expires_date_ms":"9999999999999",
                "product_id":"ishotfeixuqidingyue20220212",
                "purchase_date_ms":"9999999999999"
            }
          ]
        }
      }
    let crack_data = obj.util.jsonToObjc(json_data)
    retval.replace(crack_data);
}
let crack_better365 = {
    "onLeave": obj.util.funcToString(func_better365)
} 
obj.method.hookMethod("NSJSONSerialization","+ JSONObjectWithData:options:error:",crack_better365);
