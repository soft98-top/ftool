let better365_crack = function () {
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
obj.method.hookMethod("NSJSONSerialization","+ JSONObjectWithData:options:error:",{"onLeave":obj.util.funcToString(func_better365)});