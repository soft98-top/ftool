/**
 * all-in-one 包含所有常用函数
 * 作者：Soft98
 * 日期：2023-04-03
 * Update： 2023-11-29
 * 版本：1.0.2
 */

const obj_enum = {
    enumMethods: function (className) {
        // 枚举对象的方法
        let hookOwnMethods = ObjC.classes[className].$ownMethods;
        let hookAllMethods = ObjC.classes[className].$methods;
        let hookClasses = ObjC.classes;
        send("ownMethods: " + JSON.stringify(hookOwnMethods));
        send("methods: " + JSON.stringify(hookAllMethods));
        send("allClasses: " + JSON.stringify(hookClasses));
    },
    enumMoudles:function () {
        // 枚举模块
        var modules = Process.enumerateModules();
        for (var i = 0; i < modules.length; i++) {
            send(`== Name: ${modules[i].name}  <${modules[i].base}>`);
        }
    },
    enumExports:function (moduleName) {
        // 枚举模块导出的函数
        var exports = Module.enumerateExports(moduleName);
        for (var i = 0; i < exports.length; i++) {
            send(`== Name: ${exports[i].name}  <${exports[i].address}>`);
        }
    },
    enumImports:function (moduleName) {
        // 枚举模块导入的函数
        var imports = Module.enumerateImports(moduleName);
        for (var i = 0; i < imports.length; i++) {
            send(`== Name: ${imports[i].name}  <${imports[i].address}>`);
        }
    }
}

const obj_method = {
    getMethodInfo:function (className, methodName) {
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
    },
    invokeMethod:function (className, methodName) {
        // 调用方法
        let targetClass = ObjC.classes[className];
        let targetMethod = targetClass[methodName];
        let result = targetMethod();
        send(result);
    },
    invokeMethodWithArgs:function (className, methodName, ...args) {
        // 传递参数调用方法，可变参数
        // 调用方法
        let targetClass = ObjC.classes[className];
        let targetMethod = targetClass[methodName];
        let result = targetMethod(...args);
        send(result);
    },
    invokeMethodChain:function (className, mustMethod, ...methodNames) {
        // 链式无参调用方法
        // 调用方法
        let invokeCmd = `ObjC.classes.${className}.${mustMethod}()`;
        let methodChain = methodNames.toString().split(",");
        methodChain.forEach((methodName) => {
            invokeCmd += `.${methodName}()`;
        }
        );
        send(eval(invokeCmd));
    },
    getFuncAddr:function (module, offset) {
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
    },
    getMethodInfoByOffset:function (moduleName, offset) {
        // 获取目标函数的绝对地址
        var func_addr = obj_method.getFuncAddr(moduleName, offset);
        Interceptor.attach(ptr(func_addr), {
            // 接受可变参数
            onEnter: function (args) {
                send("====onEnter=====");
                // let index = 0;
                // console.log(args,arg2);
                // send(hexdump(ptr(args), {
                //     length: 64,
                //     header: true,
                //     ansi: true
                // }));
                // send("args: " + args + arg2);
                // for (let arg of args) {
                //     send("arg" + String(index) + ": " + arg);
                //     send(hexdump(ptr(arg), {
                //         length: 64,
                //         header: false,
                //         ansi: false
                //     }));
                // }
            },
            onLeave: function (retval) {
                send("====onLeave=====");
                send("retval: " + retval);
                // send(hexdump(ptr(retval), {
                //     length: 64,
                //     header: true,
                //     ansi: true
                // }));
            }
        });
    },
    hookMethod:function (className, methodName, cmds) {
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
    },
    hookMethodByOffset:function (moduleName, offset, cmds) {
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
    },
    getAllMethodsInfo:function (className){
        let ownMethods = ObjC.classes[className].$ownMethods;
        for(let method of ownMethods){
            obj_method.getMethodInfo(className,method);
        }
    }
}

const obj_util = {
    jsonToObjc:function (data) {
        // JSON转OC对象
        let NSString = ObjC.classes.NSString;
        let NSJSONSerialization = ObjC.classes.NSJSONSerialization;
        let strData = NSString.stringWithString_(data).dataUsingEncoding_(0x4);
        return NSJSONSerialization.JSONObjectWithData_options_error_(strData, 0x1, ptr(0x0));
    }
}

const obj = {
    enum:obj_enum,
    method:obj_method,
    util:obj_util
}

function printObj(obj){
    if (typeof obj === 'function')
        send(obj.toString())
    else{
        send(Object.keys(obj))
    }
}

function handleExec(data){
    try{
        send(eval(data));
    }catch(ex){
        send(ex)
    }
    recv(handleExec)
}

recv(handleExec)