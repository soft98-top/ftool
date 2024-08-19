/**
 * all-in-one 包含所有常用函数
 * 作者：Soft98
 * 日期：2023-04-03
 * Update： 2024-02-18
 * 版本：1.0.8
 */


/**
 * 枚举所有类
 */
var enumClasses = function() {
    let hookClasses = ObjC.classes;
    let allClasses = Object.keys(hookClasses);
    let return_str = "";
    return_str += `==allClasses==\n`;
    for (var i = 0; i < allClasses.length; i++){
        let cur_class = allClasses[i];
        return_str += `${cur_class} ${JSON.stringify(hookClasses[cur_class])}\n`;
    }
    send(return_str);
}
/**
 * 枚举对象自有方法
 * @param {string} className - 类名
 */
var enumOwnMethods = function (className) {
    // 枚举对象的方法
    let hookOwnMethods = ObjC.classes[className].$ownMethods;
    let return_str = "";
    return_str += `==${className} ownMethods==\n`;
    for (var i = 0; i < hookOwnMethods.length; i++){
        return_str += `${className} ${hookOwnMethods[i]}\n`;
    }
    send(return_str);
}
/**
 * 枚举对象的所有方法
 * @param {string} className - 类名
 */
var enumAllMethods = function (className) {
    // 枚举对象的方法
    let hookAllMethods = ObjC.classes[className].$methods;
    let return_str = "";
    return_str += `==${className} allMethods==\n`;
    for (var i = 0; i < hookAllMethods.length; i++){
        return_str += `${className} ${hookAllMethods[i]}\n`;
    }
    send(return_str);
}
/**
 * 枚举对象的方法
 * @param {string} className - 类名
 */
var enumMethods = function (className) {
    // 枚举对象的方法
    this.enumOwnMethods(className);
    this.enumAllMethods(className);
}
/**
 * 枚举模块
 */
var enumModules = function () {
    // 枚举模块
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) {
        send(`== Name: ${modules[i].name}  <${modules[i].base}>`);
    }
}
/**
 * 枚举模块导出的函数
 * @param {string} moduleName - 模块名
 */
var enumExports = function (moduleName) {
    // 枚举模块导出的函数
    var exports = Module.enumerateExports(moduleName);
    for (var i = 0; i < exports.length; i++) {
        send(`== Name: ${exports[i].name}  <${exports[i].address}>`);
    }
}
/**
 * 枚举模块导入的函数
 * @param {string} moduleName - 模块名
 */
var enumImports = function (moduleName) {
    // 枚举模块导入的函数
    var imports = Module.enumerateImports(moduleName);
    for (var i = 0; i < imports.length; i++) {
        send(`== Name: ${imports[i].name}  <${imports[i].address}>`);
    }
}


/**
 * 获取方法的信息(参数类型，返回值类型)
 * @param {string} className - 类名
 * @param {string} methodName - 方法名
 */
var getMethodInfo = function (className, methodName) {
    // 获取方法的信息(参数类型，返回值类型)
    let targetClass = ObjC.classes[className];
    Interceptor.attach(targetClass[methodName].implementation, {
        onEnter(args) {
            send(`====${className} ${methodName} onEnter=====`);
            let reciver = ObjC.Object(args[0]);
            send("Target class: " + reciver);
            send("Target class address: " + ptr(args[0]));
            let ivars = reciver.$ivars;
            for (let k in ivars) {
                let v = ivars[k];
                send(`ivars:[${k}] -> [${v}]`);
            }
            send("Target superClass: " + reciver.$superClass);
            let sel = ObjC.selectorAsString(args[1]);
            send("Hooked the target method: " + sel);
            let index = 0;
            let arg_num = methodName.split(":").length - 1;
            if (arg_num > 0) {
                while (index < arg_num) {
                    index = index + 1;
                    let obj = ObjC.Object(args[index + 1]);
                    send("Argument" + String(index) + ": " + obj.toString());
                }
            }
            send("BackTrace:" + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join(" | "));
        },
        onLeave(retval) {
            send(`====${className} ${methodName} onLeave=====`);
            let ob1 = ObjC.Object(retval);
            send("Retval: " + retval);
            send("ObjC Retval: " + ob1.toString());
            send("Type: " + ob1.$className);
            send("SuperClass: " + ob1.$superClass);
            send("");
        }
    });
}
/**
 * 调用方法
 * @param {string} className - 类名
 * @param {string} methodName - 方法名
 */
var invokeMethod = function (className, methodName) {
    // 调用方法
    let targetClass = ObjC.classes[className];
    let targetMethod = targetClass[methodName];
    let result = targetMethod();
    send(result);
}
/**
 * 传递参数调用方法，可变参数
 * @param {string} className - 类名
 * @param {string} methodName - 方法名
 * @param {...any} args - 参数列表
 */
var invokeMethodWithArgs = function (className, methodName, ...args) {
    // 传递参数调用方法，可变参数
    // 调用方法
    let targetClass = ObjC.classes[className];
    let targetMethod = targetClass[methodName];
    let result = targetMethod(...args);
    send(result);
}
/**
 * 链式无参调用方法
 * @param {string} className - 类名
 * @param {string} mustMethod - 必须调用的方法
 * @param {...string} methodNames - 链式调用的方法名列表
 */
var invokeMethodChain = function (className, mustMethod, ...methodNames) {
    // 链式无参调用方法
    // 调用方法
    let invokeCmd = `ObjC.classes.${className}.${mustMethod}()`;
    let methodChain = methodNames.toString().split(",");
    methodChain.forEach((methodName) => {
        invokeCmd += `.${methodName}()`;
    }
    );
    send(eval(invokeCmd));
}
/**
 * 根据模块名和偏移获取函数地址
 * @param {string} module - 模块名
 * @param {number} offset - 偏移量
 * @returns {NativePointer} - 函数地址
 */
var getFuncAddr = function (module, offset) {
    // 根据模块名和偏移获取函数地址
    // 根据名字获取module地址
    var base_addr = Module.findBaseAddress(module);
    send("base_addr: " + base_addr);
    send(hexdump(ptr(base_addr), {
        length: 16,
        header: true,
        ansi: true
    }));
    var func_addr = base_addr.add(offset);
    var return_addr;
    if (Process.arch == 'arm')
        return_addr = func_addr.add(1);  //如果是32位地址+1
    else
        return_addr = func_addr;
    send('func_addr: ' + return_addr);
    send(hexdump(ptr(return_addr), {
        length: 16,
        header: true,
        ansi: true
    }));
    return return_addr;
}
/**
 * 根据模块和偏移获取方法信息
 * @param {string} moduleName - 模块名
 * @param {number} offset - 偏移量
 */
var getMethodInfoByOffset = function (moduleName, offset) {
    // 获取目标函数的绝对地址
    var func_addr = obj_method.getFuncAddr(moduleName, offset);
    Interceptor.attach(ptr(func_addr), {
        // 接受可变参数
        onEnter: function (args) {
            send("====onEnter=====");
            for (let index = 0; index < this.context.argc; index++) {
                let arg = args[index];
                send("arg" + index + ": " + arg);
                send(hexdump(ptr(arg), {
                    length: 64,
                    header: false,
                    ansi: false
                }));
            }
        },
        onLeave: function (retval) {
            send("====onLeave=====");
            send("retval: " + retval);
            let ob1 = ObjC.Object(retval);
            send("retval_objc: " + ob1.toString());
            // send(hexdump(ptr(retval), {
            //     length: 64,
            //     header: false,
            //     ansi: false
            // }));
        }
    });
}
/**
 * 根据地址获取方法信息
 * @param {string} moduleName - 模块名
 * @param {number} offset - 偏移量
 */
var getMethodInfoByAddress = function (address) {
    var func_addr = address;
    Interceptor.attach(ptr(func_addr), {
        // 接受可变参数
        onEnter: function (args) {
            send("====onEnter=====");
            for (let index = 0; index < this.context.argc; index++) {
                let arg = args[index];
                send("arg" + index + ": " + arg);
                send(hexdump(ptr(arg), {
                    length: 64,
                    header: false,
                    ansi: false
                }));
            }
        },
        onLeave: function (retval) {
            send("====onLeave=====");
            send("retval: " + retval);
            let ob1 = ObjC.Object(retval);
            send("retval_objc: " + ob1.toString());
            // send(hexdump(ptr(retval), {
            //     length: 64,
            //     header: false,
            //     ansi: false
            // }));
        }
    });
}
/**
 * 获取方法的信息(参数类型，返回值类型)
 * @param {string} className - 类名
 * @param {string} methodName - 方法名
 * @param {object} cmds - 钩子命令
 */
var hookMethod = function (className, methodName, cmds) {
    // 获取方法的信息(参数类型，返回值类型)
    let targetClass = ObjC.classes[className];
    Interceptor.attach(targetClass[methodName].implementation, {
        onEnter(args) {
            send("\n================================");
            send(`====${className} ${methodName} onEnter=====`);
            let reciver = ObjC.Object(args[0]);
            let ivars = reciver.$ivars;
            let sel = ObjC.selectorAsString(args[1]);
            let index = 0;
            let arg_num = methodName.split(":").length - 1;
            let objs = [];
            if (arg_num > 0) {
                while (index < arg_num) {
                    index = index + 1;
                    let obj = ObjC.Object(args[index + 1]);
                    objs.push(obj);
                }
            }
            if (cmds["onEnter"]) {
                send(eval(cmds["onEnter"]));
            }
        },
        onLeave(retval) {
            send(`====${className} ${methodName} onLeave=====`);
            let retval_obj = ObjC.Object(retval);
            if (cmds["onLeave"]) {
                send(eval(cmds["onLeave"]));
            }
        }
    });
}
var replaceMethod = function(className, methodName, cmds) {
    // Get the target class and method
    let targetClass = ObjC.classes[className];
    let originalMethod = targetClass[methodName].implementation;

    // Create a replacement function that conditionally executes custom logic
    let replacementFunction = new NativeFunction(originalMethod.address, originalMethod.type, originalMethod.abi);
    replacementFunction.implementation = function() {
        // Get arguments and perform any necessary setup
        let args = Array.from(arguments);
        send(args)
        // let shouldExecuteCustomLogic = /* your conditional logic here */;
        return originalMethod.apply(this, args);
        if (shouldExecuteCustomLogic) {
            // Execute the custom logic
            try {
                return cmds["customFunction"] && cmds["customFunction"]();
            } catch (error) {
                send("Error in custom function:", error);
                // Consider fallback behavior if the custom function fails
            }
        } else {
            // Call the original method
            return originalMethod.apply(this, args);
        }
    };

    // Attach the replacement function using Interceptor.replace
    Interceptor.replace(originalMethod, replacementFunction);
}
/**
 * 获取目标函数的绝对地址
 * @param {string} moduleName - 模块名
 * @param {number} offset - 偏移量
 * @param {object} cmds - 钩子命令
 */
var hookMethodByOffset = function (moduleName, offset, cmds) {
    // 获取目标函数的绝对地址
    let func_addr = getFuncAddr(moduleName, offset);
    Interceptor.attach(ptr(func_addr), {
        onEnter: function (args) {
            send("\n================================");
            send(`====${moduleName} ${offset} onEnter=====`);
            let index = 0;
            if (cmds["onEnter"]) {
                send(eval(cmds["onEnter"]));
            }
        },
        onLeave: function (retval) {
            send(`====${moduleName} ${offset} onLeave=====`);
            if (cmds["onLeave"]) {
                send(eval(cmds["onLeave"]));
            }
        }
    });
}
/**
 * 获取类的所有方法的信息
 * @param {string} className - 类名
 */
var getAllMethodsInfo = function (className){
    let ownMethods = ObjC.classes[className].$ownMethods;
    for(let method of ownMethods){
        obj_method.getMethodInfo(className,method);
    }
}



/**
 * JSON转OC对象
 * @param {string} data - JSON字符串
 * @returns {object} - OC对象
 */
var jsonToObjc = function (data) {
    // 判断data是不是object，如果是转换为字符串
    if (typeof data === 'object') {
        data = JSON.stringify(data);
    }
    
    // JSON转OC对象
    let NSString = ObjC.classes.NSString;
    let NSJSONSerialization = ObjC.classes.NSJSONSerialization;
    let strData = NSString.stringWithString_(data).dataUsingEncoding_(0x4);
    return NSJSONSerialization.JSONObjectWithData_options_error_(strData, 0x1, ptr(0x0));
}
/**
 * JSON转OC对象
 * @param {string} data - JSON字符串
 * @returns {object} - OC对象
 */
var strToObjc = function (str) {
    let NSString = ObjC.classes.NSString;
    let strData = NSString.stringWithString_(obj.receipt_replace_url).dataUsingEncoding_(0x4);
    return strData
}
/**
 * 函数代码提取
 * @param {function} func - 函数对象
 * @returns {string} - 函数代码体
 */
var funcToString = function (func) {
    // 函数转字符串
    let func_str =  func.toString();
    let regex = /{([\s\S]*)}/;
    let matches = func_str.match(regex);
    let extractedCode = matches[1];
    return extractedCode;
}

/**
 * 软件版本获取
 * @returns {string} - 软件版本
 */
var getVersion = function () {
    let key = ObjC.classes.NSString.stringWithString_("CFBundleShortVersionString");
    let version = ObjC.classes.NSBundle.mainBundle().infoDictionary().valueForKey_(key).toString();
    return version;
}

/**
 * 软件架构获取
 */
var getArch = function () {
    let arch = Process.arch;
    if (arch == undefined || arch == ""){
        return "x86_64"
    }else{
        return arch
    }
}

/**
 * 打印对象或函数
 * @param {object|function} obj - 对象或函数
 */
var printObj = function(obj){
    if (typeof obj === 'function')
        send(obj.toString());
    else{
        send(Object.keys(obj));
    }
}

/**
 * 处理执行命令
 * @param {string} data - 命令字符串
 */
var handleExec = function(data){
    try{
        send(eval(data));
    }catch(ex){
        send(ex);
    }
    recv(handleExec);
}

recv(handleExec)