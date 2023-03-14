# Ptracer
Ptracer is able to display all the system calls performed by a process either attaching to a running one or executing a program.

The project supports x86_64 and AARCH64 (ARMv8) Linux platforms and ptrace is used to capture System Calls and signals.
Besides displaying them it is also possible to decode their parameters and the stack trace that has lead to them.

An Authorizer module has been included, in learning mode it is able to generate an NFA where every state is identified by 
a System Call number together with its stack trace.
In enforce mode it will ensure that all the obeserved transitions have been observed before.

This project targets ARMv8 and x86_64 platforms.

## Usage

It is mandatory to specify either a command whose execution will be traced or a process to attach to.
To specify one or another it is possible to use the command line options `--run` or `--pid` as follows:

`./ptracer --run ls -la`

```
OnePlus6T:/data/local/tmp # ps -A | grep facebook
u0_a373       4580   858 17095988 283656 SyS_epoll_wait     0 S com.facebook.katana
u0_a393       6894   858 16899220 218856 SyS_epoll_wait     0 S com.facebook.orca
OnePlus6T:/data/local/tmp # ./ptracer --pid 6894
```

Please note that in order to be able to attach to a process in Android it is necessary to run as root.

More options are available as described by the help section:

```
Ptracer usage:
  --help                     Display this help message
  --pid arg                  PID of the process to trace
  --run arg                  Run and Trace the specified program with 
                             parameters, if specified needs to be the last 
                             option
  --follow-threads arg (=1)  Trace also child threads
  --follow-children arg (=1) Trace also child processes
  --jail arg (=0)            Kill the traced process and all its children if 
                             ptracer is killed
  --backtrace arg (=1)       Extract the full stacktrace that lead to a 
                             systemcall
  --authorizer arg (=0)      Enable or disables the Authorizer module and all 
                             its options
  --learn arg (=1)           Sets the Authorizer module in learning mode
  --nfa arg                  Specifies the path where the NFA managed by the 
                             Auhtorizer is present or will be created
  --dot arg                  Specifies the path where the DOT representation of
                             the NFA managed by the Auhtorizer will be created
  --associations arg         Specifies the path where the associations between 
                             state IDs and System Calls is present or will be 
                             created by the Authorizer

Either a PID or a command to run must be specified! Use the -h option for help.
```

For example in order to attach to a specific SPID (a thread ID) and:

- follow all the threads that it will generate
- follow all the processes that it will generate
- terminate it if ptracer is terminated 
 
then the following command can be used:

`./ptracer --follow-threads true --follow-children true --jail true --backtrace --pid 6894`

The Authorizer module can be used to generate a model of the observed behaviour of a program in the form on an NFA.
This module can be in "learn" or "enforce" mode, in the first one it will create an NFA based on the observed behavior, in the
second it will stop the tracee every time a System Call, together with its stack trace, has not been encountered in previous
executions or the transition between two states has not been observed before.

In the generated NFA every state corresponds with a System Call number together with the Stack Trace that has lead to its
generation (if not explicitly disabled with the `--backtrace` option).

In order to use the Authorizer module it is necessary to specify at least the location where the NFA should be saved and the
location where the list of associations between NFA states and the combination of (System Call Number, Stack Trace) will be saved.
Optionally it is possible to generate also the DOT representation of the NFA if the `--dot` option has been specified.

The following command can be used to run the command `ls -la`, learn a new NFA from its execution and save its DOT representation:

`./ptracer --authorizer true --learn true --nfa nfa-ls.nfa --dot nfa-ls.dot --associations ass-ls.ass --run ls -la`

Please note that attaching to a process in the middle of its execution might result in unstable results when using the Authorizer
module.

## System Calls Decoders

During every execution the observed System Calls will be analyzed and a summary of them will be printed at the end.

Currently, the following System Calls Decoders have been implemented:

- ConnectDecoder: Fetches the parameters passed to the `connect` system call, in order to see all the socket opened by the tracee.
- FileDecoder: Fetches the parameters passed to the `open` system call, in order to see all the files opened by the tracee.
- PtraceDecoder: Decodes `ptrace` system calls in order to detect if the tracee is aware to be traced or if it is tracing another process.
- ReadWriteDecoder: Saves all the bytes that have been read/write from or to file descriptors, it enables to intercept every external communication.
- BinderDecoder: Decodes the ioctl syscall when used to communicate with the Android Binder IPC

More decoders will be implemented in the future.

## Dependencies

The project dependencies tree can be seen below:
```
ptracer
├─ boost 1.80.0 (Conan)
├─ android-ndk r25 - (Conan)
├─ libalf
├─ libunwindstack-ndk
│  ├─ lzma-ndk
│  ├─ libdexfile-ndk
│  │  ├─ libartbase-ndk
│  │  │  ├─ libziparchive-ndk
│  │  │  │  ├─ libbase-ndk
│  │  │  ├─ libtinyxml2
│  │  │  ├─ libartpalette-ndk
│  │  │  ├─ libbase-ndk
│  │  │  ├─ liblog-ndk
│  │  │  │  ├─ libcutils-ndk
│  │  │  │  ├─ libutils-ndk
│  │  │  │  ├─ libsystem-ndk
│  │  │  ├─ libcap-official
│  │  ├─ libartpalette-ndk
│  │  ├─ libziparchive-ndk
│  │  │  ├─ libbase-ndk
│  │  ├─ libbase-ndk
```

## Build

The following tools are expected to be pre-installed to be able to compile the project:

- [Conan](https://conan.io/) version 1.50 or above: Used to handle dependencies like Boost and Android NDK. 
- [CMake](https://cmake.org/) version 3.23 or above: Use to control the software compilation and link together all the other dependencies.

Depending on what architecture you are targeting it is possible to use the following build scripts in order to properly invoke Conan and
CMake:

- `./build/aarch64/build.sh`: Used to build an executable and statically linked library for ARMv8 architectures
- `./build/x86_64/build.sh`: Used to build an executable and statically linked library for x86_64 architectures but not Android
- `./build/x86_64-android/build.sh`: Used to build an executable and statically linked library for x86_64 architectures running Android

Once it has terminated the `ptracer` executable will be in `./build/$ARCH/cmake-build-debug/bin` and the statically and dynamically linked
libraries will be in `./build/$ARCH/cmake-build-debug/lib`.

It has been necessary to subdivide the build for x86_64 architectures running Android and not because the last ones will benefit from the
stack unwinding capabilities of `libunwindstack` and to do that it requires to be compiled using Android NDK. 

## Debug
The project uses the user-defined signal SIGUSR1, and by default GDB will stop at every signal, to modify this behaviour it
is possible to use the following:
```
handle SIGUSR1 nostop noprint pass
```
This can be done automatically by putting this command into your `~/.gdbinit` file.

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

In case the Android system is not directly reachable (e.g., it is an emulated instance in Android Studio), then it is possible to forward
a socket connection using the `adb` utility tool.
For example in order to forward the local TCP port 5000 to the Android TCP port 5001, it is possible to use the following command:

```
adb forward tcp:5000 tcp:50001
```

For more informatio regarding `adb` and forwarding check its manual [here](https://developer.android.com/studio/command-line/adb#forwardports).
