# litevault

litevault is a command line password manager that allows you to safely store
and retrieve your passwords and keep the vault file on github or other public
repositories

## Installation
### Simplest method
The simplest way to install is:
```
sudo apt-get install xautomation  # provides the xte command
sudo pip install litevault
```

### Alternate method
The only dependencies of litevault are the **scrypt** python package and
the **xautomation** package. **litevault** is a single python file,
`litevault.py`. Therefore installation can simply be installing the
dependencies and doing:
```
sudo cp litevault.py /usr/bin/litevault
sudo chmod a+x /usr/bin/litevault
```

## Use
- run `litevault` with the desired commands
    - store your usernames, passwords and info as items
    - retrieve a password with `p item` or just `item`
- bind `litevault -s` to a key combination in your OS. This will cause
    the active **litevault** instance to send the stored password
    through your keyboard

### OS Configurations
**Please submit your configuration if your Window Manger isn't listed**


**[i3wm](https://i3wm.org/)**
in your `~/.i3` or `~/.config/i3/config`
```
# Create a litevault scratchpad
exec urxvt -name litevault --hold -e litevault -f ~/.config/vault
for_window [title="^litevault"] move to scratchpad

# setup the "send password" command
bindsym $mod+p exec python ~/projects/litevault/litevault.py -s &

# setup the "show litevault scratchpad" command
bindsym $mod+Shift+p [title="^litevault"] scratchpad show
```

## Features
- simple: documented command line interface
- encryption: litevalt utilizes the scrypt encryption algorithm, which
    requires a high amount of memory and cpu processing time to crack
- secure: litevault keeps everything in memory, never exposing your
    passwords to the `ps` command or to your file system (there is one
    exception, see Not on Info Editing with Editor). When passwords are
    transfered, they are transferred using `xte` to simulate keypresses on
    your keyboard.

## Command Line Options
see litevault -h

## Program Options
type 'h' or '?' while running the program

## Note on Info Editing with Editor
There is one instance where litevault will stored entered text onto the
"filesystem" and that is when you use the 'e' command when editing the INFO
field.

litevault creates a temporary file with only the user privileges (-rw------)
in a ramfs (/dev/shm) directory. This means that the file is only stored in ram.
As soon as your editing session completes, litevault pulls the data and deletes
the file.

If someone else was logged in as your user or root, they could access the file
during this time. More importantly, your editor might store information in temp
files -- this functionality should be disabled through command line options.

Examples:
    `litevault -e 'nano -R'`: use nano in restricted mode (default)
    `litevault -e 'vim -Zu NONE'`: use vim in restricted mode without any plugins

In order to avoid this 'leak', don't use the `e` option when editing highly
sensitive information

# FAQ
**Is litevault secure**
This has two answers
- litevault is a single python file with less than 600 lines as of this writing.
    it would be simple for you to look through it yourself and at least note
    that:
    - it does not import any web modules and therefore (probably) does not
        communicate with the web
    - it writes to a file in only one documented place
    - when it uses subprocess, it communicates all sensitive data through
        stdin (not at the command line), which means that the info cannot
        be seen by external processes
- litevault was intended to be as secure as possible. However, it is in the
    Beta stages and does not currently have any peer review. However, to
    write **litevault** the author did a fair amount of research into the best
    encryption algorithms. Feel free to look over the following links.
    - [scrypt wikipedia](https://en.wikipedia.org/wiki/Scrypt) -- scrypt is intended
        to be difficult to crack with brute force, and is used with many
        cryptocurrencies like litecoin
    - [do security experts recommend bcrypt (or why scrypt is better)](http://security.stackexchange.com/questions/4781/do-any-security-experts-recommend-bcrypt-for-password-storage)
    - [why I **don't** recommend scrypt](http://blog.ircmaxell.com/2014/03/why-i-dont-recommend-scrypt.html) Written in 2014, this blog post provides a good set of reasons **not** to use scrypt, and what settings scrypt needs to be set at for it to be effective. Particularily, it must have maxmem > 4mb (litevault default=256mb)

**Why didn't you use openssl?**
- I had wanted to use openssl initially, but found it to have several problems.
    In particular, I had no simple way of interfacing with it over the
    command line with python. Secondly, you have tomake sure your password has
    very high entropy in openssl, as it
    [does nothing to obfuscate it](http://security.stackexchange.com/questions/29106/openssl-recover-key-and-iv-by-passphrase)

