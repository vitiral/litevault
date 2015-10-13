# litevault -- the lightweight command line password manager

litevault provides an ultra lightweight command line password manager

## Installation
litevault is a single file that can run on any system that has python 2.6+ (including python3+).
It has two dependencies:
- xdotool from Xorg
- openssl

To install, simply copy the litevault file into /usr/bin or wherever you put your user executables


## Use

litevault follows the KISS (Keep It Simple Stupid) principle as much as possible. Use it as follows:
- install it (see above)
- store passwords in [.ini syntax](https://docs.python.org/3/library/configparser.html)
    in a `aes-256-cbc` encrypted file with `salt` enabled.
    - an example file is in `examples/plain.txt`. An example encrypted file is `examples/encrypted.aes` with
        password `hello`
    - Default location is `~/.auth.aes`
    - [openssl.vim](https://github.com/vim-scripts/openssl.vim) is a recommended method of writing
        your vault file
- run `litevault` from the command line, you will be prompted for a password to unlock you vault
    - run `litevault -h` for help
- You can now type a command to retrieve a password or info. Type `?` or `h` to get help
- Once a password has been retrieved, you just use the following command to have it typed out
    on your keyboard: `litevault -s`
- it is recommended that you set this command to a key combination in your window manager
