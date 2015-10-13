from __future__ import print_function

import os
import sys
import time
import getpass
import subprocess
import signal
import argparse
try:
    import configparser
except ImportError:
    import ConfigParser as configparser

pid_file = '/tmp/litevault.pid'
intro_msg = 'litevault started. Type "?" or "h" for help'
help_msg = '''
Help:
h or ?      = help
q           = quit
No Argument = get all (same as 'a')
l           = list items
u           = get user
p           = get password
i           = get info
a           = get both user and password (insert a TAB between them and end with Return)
'''


def pplist(l, cols=4, indent=0):
    if not isinstance(l, list):
        l = list(l)
    while len(l) % cols != 0:
        l.append(" ")
    step = len(l) // cols
    step = step if step != 0 else 1
    split = [l[i:i + len(l) // cols] for i in range(0, len(l), step)]
    for row in zip(*split):
        print(' ' * indent + "".join(str.ljust(i, 20) for i in row))


class Vault(object):
    def __init__(self, path, encryption, password):
        self.path = path
        self.encryption = encryption
        self.password = password

    def get_vault(self):
        cmd = ssl_load.format(method=self.encryption, path=self.path)
        p = subprocess.Popen(cmd.encode().split(),
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        p.stdin.write(self.password.encode())
        stdout, stderr = p.communicate()
        assert not stderr
        vault = configparser.ConfigParser()
        vault.read_string(stdout.decode())
        return vault

    def __getitem__(self, item):
        vault = self.get_vault()
        if item not in vault:
            print("item '{}' not found".format(item))
            return
        return vault[item]

    def __iter__(self):
        vault = self.get_vault()
        out = iter(vault.keys())
        next(out)  # remove DEFAULT
        return out


def clear_screen(msg=None):
    if msg is None:
        msg = '\n ** Press ENTER to clear the screen **'
    out = input(msg)
    print('\x1b[0;0H\x1b[2J\n' + intro_msg)
    return out


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
    '\t': 'Tab',
    '\n': 'Return',
}


def load_info(item, vault):
    value = vault[item]
    if value is None:
        return
    key = 'i' if 'i' in value else 'info' if 'info' in value else None
    if key is None:
        print('!! No info for {} !!'.format(item))
        return
    info = value[key]
    print('\n ** Info **\n'.format(item) + info)
    clear_screen()
    return


def load_password(item, vault, append=False):
    global curpass
    value = vault[item]
    key = 'p' if 'p' in value else 'password' if 'password' in value else None
    if key is None:
        print('!! no password for {} !!'.format(item))
        curpass = ''
        return
    if append:
        curpass += '\t' + value[key] + '\n'
    else:
        curpass = value[key]
    print("  Password ready for: {}".format(item))


def load_user(item, vault):
    global curpass
    value = vault[item]
    key = 'u' if 'u' in value else 'username' if 'username' in value else None
    if key is None:
        print('!! no username for {} !!'.format(item))
        curpass = ''
        return
    curpass = value[key]
    print("  Username ready for: {}".format(item))


def load_all(item, vault):
    load_user(item, vault)
    load_password(item, vault, append=True)


def output_password(signum, stack):
    '''Output the password on the keyboard'''
    if not curpass:
        return
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


def list_items(vault):
    print('\n ** Items **')
    pplist(list(vault))
    user_input = clear_screen("command: ")
    if not user_input:
        return
    execute_command(vault, user_input)


def execute_command(vault, user_input):
    print_help = lambda item: print(help_msg)
    interface = {
        '?': print_help,
        'h': print_help,
        'l': lambda item: list_items(vault),
        'u': lambda item: load_username(item, vault),
        'p': lambda item: load_password(item, vault),
        'i': lambda item: load_info(item, vault),
        'a': lambda item: load_all(item, vault),
        'q': lambda item: sys.exit(0)
    }
    user_input = user_input.split()
    cmd = user_input[0]
    if cmd not in interface:
        cmd = 'a'
        item = user_input[0]
    else:
        if len(user_input) > 1:
            cmd, item = user_input
        else:
            cmd, = user_input
            item = None
    return interface[cmd](item)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--send_stored_pass', action='store_true')
    parser.add_argument('-w', '--wait', default=0.25, help="Wait time before sending the stored password")
    parser.add_argument('-p', '--password', help='Use only in testing (not secure)')
    parser.add_argument('-f', '--file', default='pass.aes',
                        help='password file to load')
    parser.add_argument('-e', '--encryption', default='aes-256-cbc',
                        help='default encryption method to use')
    args = parser.parse_args()
    verify_environment()
    if args.send_stored_pass:
        with open(pid_file, 'rb') as f:
            pid = int(f.read())
        time.sleep(args.wait)
        subprocess.check_output('kill -10 {}'.format(pid).encode(), shell=True)
        sys.exit()
    if not args.password:
        args.password = getpass.getpass("Decryption password: ")
    signal.signal(signal.SIGUSR1, output_password)
    print(intro_msg)
    with open(pid_file, 'w') as f:
        f.write(str(os.getpid()))
    vault = Vault(path=args.file, encryption=args.encryption, password=args.password)
    del args, parser
    del sys.argv[1:]
    while True:
        user_input = input("command: ")
        if not user_input:
            continue
        execute_command(vault, user_input)


if __name__ == '__main__':
    main()
