# Ptracer
Ptracer is able to display all the system calls performed by a process either attaching to a running one or executing a program.

## Debug
Use the following to prevent GDB from stopping for each SIGUSR1 signal:
```
handle SIGPIPE nostop noprint pass
```
This can be done automatically by putting this command into your ~/.gdbinit file.

Debugging native Android applications can be done using GDB server which can be found in adb push `$ANDROID_SDK/ndk-bundle/prebuilt/android-arm64/gdbserver/gdbserver`
and copied on the device with the following command:
```
adb push $ANDROID_SDK/ndk-bundle/prebuilt/android-arm64/gdbserver/gdbserver /data/local/tmp/
```
The folder `/data/local/tmp/` is used since executables in there are allowed to be executed.

GDB Server can be used as follows:
```
./gdbserver --once 0.0.0.0:7777 ./ptracer --run ls -la
```