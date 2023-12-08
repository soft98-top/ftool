let paddle_trial = function () {
    const reciver = ObjC.Object(args[0]);
    reciver.resetTrial();
    console.log("Reset Trial Success!");
}
obj.method.hookMethod("PADProduct","- trialDaysRemaining",{"onEnter":obj.util.funcToString(paddle_trial)});