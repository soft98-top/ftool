let payload_better365 = {
    "onLeave":`let data = ObjC.Object(retval);
    let key_receipt = ObjC.classes.NSString.stringWithString_('receipt'); 
    let receipt = data.objectForKeyedSubscript_(key_receipt);
    let key_in_app = ObjC.classes.NSString.stringWithString_('in_app'); 
    let key_expires_date_ms = ObjC.classes.NSString.stringWithString_('expires_date_ms');
    let key_product_id = ObjC.classes.NSString.stringWithString_('product_id');
    let data_product_id = ObjC.classes.NSString.stringWithString_('ishotfeixuqidingyue20220212');
    let key_purchase_date_ms = ObjC.classes.NSString.stringWithString_('purchase_date_ms');
    let dict = ObjC.classes.NSMutableDictionary.alloc().init();
    dict.setObject_forKey_(9999999999999,key_expires_date_ms);
    dict.setObject_forKey_(9999999999999,key_purchase_date_ms);
    dict.setObject_forKey_(data_product_id,key_product_id);
    let info_array = ObjC.classes.NSMutableArray.alloc().init();
    info_array.addObject_(dict);
    let receipt1 = receipt.mutableCopy();
    receipt1.setObject_forKey_(info_array,key_in_app);
    let replace_data = data.mutableCopy();
    replace_data.setObject_forKey_(receipt1,key_receipt);
    retval.replace(replace_data);
    send("Crack Success!");`
}
obj.method.hookMethod("NSJSONSerialization","+ JSONObjectWithData:options:error:",payload_better365);
