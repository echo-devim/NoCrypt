# NoCrypt - AntiRansomware Linux Kernel Module
A small experimental project to make a defense tool to prevent ransomware attacks on Linux systems.

The module hooks the system call `sys_rename` using ftrace to monitor all the files renamed on the system.

Ransomware often encrypt a lot of files renaming them with the same suffix.
NoCrypt checks if a process renames a file with a known ransomware suffix, killing the process and printing a log in JSON format in the message buffer of the kernel (use dmesg to view it).

NoCrypt has also a small behaviour check, if the same process starts to rename many files, after 12 renamed files by default, it'll be killed.

The module has also a self-protection mechanism, in fact it hides from the system avoiding to be unloaded. Providing the right password it is possible to make it visible and then unload it.

**Consider this project a proof-of-concept you can easily customize for your needs. I don't take any responsibility.**


Thanks to Immutable-file-linux project of Shubham Dubey

Reference for: https://nixhacker.com/hooking-syscalls-in-linux-using-ftrace


## Instructions
* Run `make` from terminal
* Load the module using `sudo insmod nocrypt.ko "max_rename=20" "behaviour_detection=true" "password=your-P4ss"`

**Note:** `insmod` loads the kernel module until the system is rebooted. If you want to make this module persistent, ask to your sysadmins.

The module prints all its logs into the kernel message buffer (use `dmesg` command to see them). When a ransomware attack is detected, the module will print event logs in JSON format to be more parsable by other systems.
Nocrypt will start hiding the module frome the system and creating a sys file into `/sys/kernel/.nocrypt/nocrypt` with only root rw permissions.

If you try to execute the command `lsmod | grep nocrypt` or `rmmod nocrypt`, you'll fail. In order to unlock the module, making it visible again, run this command:
```sh
# echo -n "your-P4ss" > /sys/kernel/.nocrypt/nocrypt
```

The default password is `n0Cr1pt`. After that command you can perform `rmmod`.

The attackers can find the module (for example viewing the dmesg), but they shouldn't be able to unload it so easily.
See the end notes for further possible improvements.

## Example
Compile the example program `gcc -o example example.c`.
Now run it `.\example`, it will try to rename several test files into .lockbit.
Even if the input files don't exist, NoCrypt will kill the process because it's trying to rename files with a blacklisted extension.
Check the module output with `sudo dmesg`

# Notes
Possible improvements that are unlikely will be implemented in this PoC project:
- Dump process memory
- Print logs into a internal buffer accessible via sysfs (partially implemented)
- Hide completely the module from the system, thus attackers won't know if there is installed nocrypt
- Add more self-protection mechanisms
- Hook more syscalls, perform more checks

If you use this project or you extend it, please cite or link this repo and its original author.