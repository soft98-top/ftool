let exec_func = function(){
    let retval_obj = ObjC.Object(retval);
    let original_url = retval_obj.URL().toString()
    send(original_url)
    if(original_url == "https://buy.itunes.apple.com/verifyReceipt"){
        let replace_url = "http://127.0.0.1:10012/verifyReceipt"
        let NSURL = ObjC.classes.NSURL;
        let replace_obj = NSURL.URLWithString_(replace_url);
        send(replace_obj.toString())
        retval_obj.setURL_(replace_obj)
    }
}
hookMethod("NSMutableURLRequest","+ requestWithURL:",{
    "onLeave": funcToString(exec_func)
})

