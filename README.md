# NoCrypt - AntiRansomware Linux Kernel Module
A small experimental project to make a defense tool to prevent ransomware attacks on Linux systems.

The module hooks the system call `sys_rename` using ftrace to monitor all the files renamed on the system.

Ransomware often encrypt a lot of files renaming them with the same suffix.
NoCrypt checks if a process renames a file with a known ransomware suffix, killing the process and printing a log in the message buffer of the kernel (use dmesg to view it).

NoCrypt has also a small behaviour check, if the same (parent) process starts to rename many files, after 12 renamed files by default, it'll be killed.
The module monitors the parent task because often ransomware are command line tools with multiple threads (different task structs).

**Consider this project a proof-of-concept you can easily customize for your needs. Actually it is not recommended to put it in production.**


Thanks to Immutable-file-linux project of Shubham Dubey

Reference for: https://nixhacker.com/hooking-syscalls-in-linux-using-ftrace


## Instructions
* Run `make` from terminal
* Load the module using `sudo insmod nocrypt.ko "max_rename=12" "behaviour_detection=true"`

## Example
Compile the example program `gcc -o example example.c`.
Now run it `.\example`, it will try to rename several test files into .lockbit.
Even if the input files don't exist, NoCrypt will kill the process because it's trying to rename files with a blacklisted extension.
Check the module output with `sudo dmesg`
