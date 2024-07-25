# get_signal_desktop_key
Since Signal Desktop 7.17, the cipher key used to read the database is encrypted. This program attempts to decrypt the key. For this it tries to read a password from the your keyring/wallet/collection (name varies based on implementation) through `dbus`.

# Requirements

Note this program is Linux only. For Windows, decrypting the keys is already part of [signalbackup-tools](https://github.com/bepaald/signalbackup-tools).

This program depends on
- A c++ compiler, supporting c++17
- dbus (make sure to install the development package if your distro provides them separately, for example on Debian: `libdbus-1-dev`)
- openssl (again, development package)

# Compile

Simple compile:
```
g++ -std=c++17 *.cc $(pkg-config --libs --cflags dbus-1) -lcrypto -o get_signal_desktop_key
```

Change/add any options if you know better.

# Run

Simply run the binary from the command line:

```
$ ./get_signal_desktop_key
```
The program expects to find the Signal Desktop config file in `~/.config/Signal/config.json`. If your config file is at a different location (or you're on the Beta), you can supply it as an argument to the program. For example:
```
$./get_signal_desktop_key ~/.config/Signal Beta/json.config
```

If the program works, you could let me know be leaving a thumbs up in [Issue #1](https://github.com/bepaald/get_signal_desktop_key/issues/1). 

If the program consistently fails, try adding `-v` to the command line for more verbose output, and opening an issue.

# Future plans

It is planned to incorparate this functionality into [signalbackup-tools](https://github.com/bepaald/signalbackup-tools) in the future. However, for now
- I am very short on time
- I am new to dbus, and think this code needs a lot more going over
- I am very unsure currently if it works at all for most people.
