let paddle_trial = function () {
    const reciver = ObjC.Object(args[0]);
    reciver.resetTrial();
    send("Reset Trial Success!");
}
hookMethod("PADProduct","- trialDaysRemaining",{"onEnter":funcToString(paddle_trial)});