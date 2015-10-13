from __future__ import print_function

import os
import sys
import pprint
import time
import getpass
import subprocess
import signal
import argparse

import yaml

inftro_msg = 'pman started. Type "?" or "h" for help'
help_msg = '''
Help:
h or ?      = help
No Argument = get password
p           = get password
i           = get info
q           = quit
'''

clear_screen = lambda: print('\x1b[0;0H\x1b[2J\n' + inftro_msg)

ssl_load = "openssl {method} -d -salt -pass stdin -in {path}"
# curpass = '''my secret password ~`!@#$%^&*()-_+=[]{}|\\,.<>?/'" '''
curpass = ''

# http://www.linux.org/threads/xdotool-keyboard.6414/
xdochars = {
    '~': 'asciitilde',
    '`': 'quoteleft',
    '!': 'exclam',      # sp
    '@': 'at',
    '#': 'numbersign',
    '$': 'dollar',
    '%': 'percent',
    '^': 'asciicircum',
    '&': 'ampersand',
    '*': 'asterisk',
    '(': 'parenleft',
    ')': 'parenright',
    '-': 'minus',
    '_': 'underscore',
    '+': 'plus',
    '=': 'equal',
    '[': 'bracketleft',
    '{': 'braceleft',
    ']': 'bracketright',
    '}': 'braceright',
    '|': 'bar',
    '\\': 'backslash',
    ':': 'colon',
    ';': 'semicolon',
    '"': 'quotedbl',
    "'": 'quoteright',
    ',': 'comma',
    '<': 'less',
    '.': 'period',
    '>': 'greater',
    '/': 'slash',
    '?': 'question',
    ' ': 'space',
    '\n': None,  # error
}


def load_item(item, encryption, path, decrypt_pass, info=False):
    global curpass
    cmd = ssl_load.format(method=encryption, path=path)
    p = subprocess.Popen(cmd.encode().split(),
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    p.stdin.write(decrypt_pass.encode())
    stdout, stderr = p.communicate()
    assert not stderr
    passwords = yaml.load(stdout)
    if item not in passwords:
        print("item '{}' not found".format(item))
        return
    if info:
        info = passwords[item]['info']
        pprint.pprint(info)
        input("\n** Press Enter to clear screen **")
        clear_screen()
    else:
        curpass = passwords[item]['password']


def output_password(signum, stack):
    '''Output the password on the keyboard'''
    k = ' key '
    characters = [c if c not in xdochars else xdochars[c]
                  for c in curpass]
    args = k + k.join(characters)
    subprocess.check_call(('xdotool ' + args).encode().split())


def verify_environment():
    requirements = {
        'openssl': 'openssl version',
        "Xorg's xdotool": 'xdotool --version',
    }
    for r, cmd in requirements.items():
        try:
            subprocess.check_output(cmd.split())
        except Exception as E:
            print('Dependency not met: {}'.format(r))
            sys.exit(1)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--password', help='Use only in testing (not secure)')
    parser.add_argument('-f', '--file', default='pass.aes',
                        help='password file to load')
    parser.add_argument('-e', '--encryption', default='aes-256-cbc',
                        help='default encryption method to use')
    args = parser.parse_args()
    verify_environment()
    if not args.password:
        args.password = getpass.getpass("Decryption password: ")
    signal.signal(signal.SIGUSR1, output_password)
    print(inftro_msg)
    with open('/tmp/pman.pid', 'w') as f:
        f.write(str(os.getpid()))
    print_help = lambda item: print(help_msg)
    interface = {
        '?': print_help,
        'h': print_help,
        'p': lambda item: load_item(item, args.encryption, args.file, args.password),
        'i': lambda item: load_item(item, args.encryption, args.file, args.password, info=True),
        'q': lambda item: sys.exit(0)
    }
    while True:
        uin = input("command: ").split()
        if not uin:
            continue
        cmd = uin[0]
        if cmd not in interface:
            cmd = 'p'
            item = uin[0]
        else:
            if len(uin) > 1:
                cmd, item = uin
            else:
                cmd, = uin
                item = None
        interface[cmd](item)
    print(load_password(args.encryption, args.file, args.password, 'home'))


if __name__ == '__main__':
    main()
