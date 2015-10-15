#!/usr/bin/python
from __future__ import print_function

import os
import sys
import re
import json
import time
import random
import string
import getpass
import subprocess
import signal
import select
import argparse

import scrypt

# Python 2 & 3 compatibility
if sys.version_info[0] == 2:
    input = raw_input

# Global current stored password
curpass = ''

##################################################
# Constants

pid_file = '/tmp/litevault.pid'
intro_msg = 'litevault started. Type "?" or "h" for help'
help_msg = '''
Help:
h or ?         = help
q or exit      = quit
s or save      = save vault state to file
n              = set new password for vault (and save it)
NONMATCHING [] = get all of item (same as 'a')
l or ls     [] = list items. Add an item to do a fuzzy search
u           [] = get user
p           [] = get password
i           [] = get info
a           [] = get both user and password (insert a TAB between them and end with Return)
c           [] = create/overwrite item in vault  * (in memory. Use 's' to save changes to file)
d or rm     [] = delete data from vault          * (in memory, use 's' to save changes to file)
'''


##################################################
# xdotool mappings
# http://www.linux.org/threads/xdotool-keyboard.6414/

xdotool_char_mappings = {
    '~': 'asciitilde'   , '`': 'quoteleft'   , '!': 'exclam'       , '@': 'at'          ,
    '#': 'numbersign'   , '$': 'dollar'      , '%': 'percent'      , '^': 'asciicircum' ,
    '&': 'ampersand'    , '*': 'asterisk'    , '(': 'parenleft'    , ')': 'parenright'  ,
    '-': 'minus'        , '_': 'underscore'  , '+': 'plus'         , '=': 'equal'       ,
    '[': 'bracketleft'  , '{': 'braceleft'   , ']': 'bracketright' , '}': 'braceright'  ,
    '|': 'bar'          , '\\': 'backslash'  , ':': 'colon'        , ';': 'semicolon'   ,
    '"': 'quotedbl'     , "'": 'quoteright'  , ',': 'comma'        , '<': 'less'        ,
    '.': 'period'       , '>': 'greater'     , '/': 'slash'        , '?': 'question'    ,
    ' ': 'space'        , '\t': 'Tab'        , '\n': 'Return'      ,
}


##################################################
# Convenience Functions


def set_password_dialog(first_message="New Password: "):
    while True:
        p1 = getpass.getpass(first_message)
        if not p1:
            print("No password receiving, skipping")
            return None
        p2 = getpass.getpass("Enter the same password: ")
        if p1 == p2:
            return p1
        else:
            print("Passwords don't match. Retrying...")

def print_item_not_found(item):
    print("Item not found {}".format(item))

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


def clear_screen(msg=True):
    out = ''
    if msg:
        if msg is True:
            msg = '\n ** Press ENTER to clear the screen **'
        out = input(msg)
    print('\x1b[0;0H\x1b[2J\n' + intro_msg)
    return out


def output_password(signum, stack):
    '''Output the password on the keyboard'''
    if not curpass:
        return
    k = ' key '
    characters = [c if c not in xdotool_char_mappings else xdotool_char_mappings[c]
                  for c in curpass]
    args = k + k.join(characters)
    subprocess.check_call(('xdotool ' + args).encode().split())


def verify_environment():
    requirements = {
        "Xorg's xdotool": 'xdotool --version',
    }
    for r, cmd in requirements.items():
        try:
            subprocess.check_output(cmd.split())
        except Exception as E:
            print('Dependency not met: {}'.format(r))
            sys.exit(1)


def input_eof(msg=''):
    print(msg)
    text = [input(" ** Press Cntrl+D to finish or ENTER to skip **\n> ")]
    if not text[0]:
        return ''
    while True:
        try:
            text.append(input('> '))
        except EOFError:
            return '\n'.join(text)


def generate_password(length):
    chars = string.ascii_letters + string.digits + '!@#$%^&*()'
    random.seed = (os.urandom(1024))
    return ''.join(random.choice(chars) for i in range(length))

##################################################
# Conveinience Functions

class Vault(dict):
    """Safe password storage and retrieval"""

    def __init__(self, path, password, maxtime=2, initial_data=None):
        """
        :path: path to vault file
        :password: password to open file
        """
        self.path = path
        self.password = password
        self.maxtime = maxtime
        if initial_data:
            dict.__init__(self, initial_data)
        else:
            dict.__init__(self)
            self._load_passwords()

    def _load_passwords(self):
        if not os.path.exists(self.path):
            self.clear()
            return
        with open(self.path, 'rb') as f:
            encrypted = f.read()
        text = scrypt.decrypt(encrypted, self.password, maxtime=self.maxtime * 3)
        data = json.loads(text)
        self.clear()
        self.update(data)

    def _dump_passwords(self, passwords=None):
        if passwords is not None:
            self.clear()
            self.update(passwords)
        text = json.dumps(self)
        encrypted = scrypt.encrypt(text, self.password, maxtime=self.maxtime)
        with open(self.path, 'wb') as f:
            f.write(encrypted)

    def save(self, passwords=None):
        self._dump_passwords(passwords)


##################################################
# User Functions

##################################################
# Loading and Viewing

def load_info(vault, item):
    if item not in vault:
        print_item_not_found(item)
        return
    value = vault[item]
    key = 'i' if 'i' in value else 'info' if 'info' in value else None
    if key is None:
        print('!! No info for {} !!'.format(item))
        return
    info = value[key]
    print('\n ** Info **\n'.format(item) + info)
    clear_screen()
    return


def load_password(vault, item, append=False):
    if item not in vault:
        print_item_not_found(item)
        return
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


def load_user(vault, item):
    if item not in vault:
        print_item_not_found(item)
        return
    global curpass
    value = vault[item]
    if value is None:
        return
    key = 'u' if 'u' in value else 'username' if 'username' in value else None
    if key is None:
        print('!! no username for {} !!'.format(item))
        curpass = ''
        return
    curpass = value[key]
    print("  Username ready for: {}".format(item))


def load_all(vault, item):
    if item not in vault:
        print_item_not_found(item)
        return
    load_user(vault, item)
    load_password(vault, item, append=True)
    load_info(vault, item)


def list_items(vault, item=None):
    print('\n ** Items **')
    if item is None:
        items = list(vault)
    else:
        pat = re.compile(r'.*?'.join(item))
        items = [i for i in vault if pat.search(i)]
    pplist(items)
    user_input = clear_screen("command: ")
    if not user_input:
        return
    execute_command(vault, user_input)


##################################################
# Creating, Deleting, and Saving

def create_item(vault, item):
    if item in vault:
        print("NOTICE: {} already exists in vault".format(item))
    print(" ** Type in the value for each.                                               **\n"
          " ** To skip a field (and not change it), press ENTER without typing anything. **\n"
          " ** To quit (and not store) type q for any field.                             **")
    username = input("username: ")
    quit_msg = "Got 'q' -- Quiting"
    if username == 'q':
        print(quit_msg)
        return
    print(" ** Enter password. Enter g [number] to generate a random              **\n"
          " ** password of length `number` (defaults to 32 if no input specified) **")
    password = getpass.getpass("password: ")
    if password == 'q':
        print(quit_msg)
        return
    if password[0:2].strip() == 'g':
        length = password[2:]
        if length:
            # if length isn't valid, re-ask until it is
            while True:
                try:
                    length = int(length)
                    break
                except ValueError:
                    print("!! length must be integer, got: [{}] !!".format(length))
                    length = input("length: ").strip()
                    if length == 'q':
                        print(quit_msg)
                        return
        else:
            length = 32
        password = generate_password(length)
    info = input_eof("** info:").strip()
    if info == 'q':
        print(quit_msg)
        return
    if not (username or password or info):
        return
    load = False
    if item not in vault:
        vault[item] = {}
        load = True
    value = vault[item]
    if username:
        value['u'] = username
    if password:
        value['p'] = password
    if info:
        value['i'] = info
    clear_screen(False)
    print(" ** Stored {}. Use 's' to save to file **".format(item))
    if load:
        print(" ** Loading new item's password **")
        load_password(vault, item)

def delete_item(vault, item):
    if item not in vault:
        print("Item {} not in vault".format(item))
        return
    if input("Would you really like to delete {}? (y/n)".format(item)).lower()[:1] in ('n', ''):
        print("Not deleting")
        return
    vault.pop(item)
    print("Deleted. Use 's' to save to file")


def save_vault(vault, *args):
    vault.save()
    print("Vault Saved")


def new_password(vault, *args):
    newpass = set_password_dialog()
    if not newpass:
        print("No password entered, skipping")
        return
    vault.save()
    vault.password = newpass
    vault.save()
    print("Vault with new password saved")




##################################################
# Other User Functions

def clear_password():
    global curpass
    curpass = ''
    clear_screen(False)


def execute_command(vault, user_input):
    print_help = lambda vault, item: print(help_msg)
    quit = lambda vault, item: sys.exit(0)
    interface = {
        '?': print_help,    'h': print_help,
        'q': quit,          'exit': quit,
        'l': list_items,    'ls': list_items,
        'd': delete_item,   'rm': delete_item,
        'u': load_user,
        'p': load_password,
        'i': load_info,
        'a': load_all,
        'c': create_item,
        's': save_vault,
        'n': new_password,
    }
    user_input = user_input.split()
    cmd = user_input[0]
    if cmd not in interface:
        cmd = 'a'
        item = ' '.join(user_input)
        print("Defaulting to command 'a'")
    else:
        if len(user_input) > 1:
            cmd = user_input[0]
            item = ' '.join(user_input[1:])
        else:
            cmd, = user_input
            item = None
    return interface[cmd](vault, item)


def timeout_loop(vault):
    clear_screen(msg=False)
    print(' ** litevault timed out **')
    while True:
        pwd = getpass.getpass("Enter password: ")
        if pwd == vault.password:
            return
        time.sleep(3)
        print("!! Incorrect password")


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--send_stored_pass', action='store_true')
    parser.add_argument('-w', '--wait', default=0.25, help="Wait time before sending the stored password")
    parser.add_argument('-p', '--password', help='Use only in testing, not secure!')
    parser.add_argument('-f', '--file', default='~/.vault',
                        help='password file to load. Default is ~/.vault')
    parser.add_argument('-t', '--timeout', default=300, type=float,
                        help='time in seconds before program is locked with no activity (default=300)')
    args = parser.parse_args()
    verify_environment()
    if args.send_stored_pass:
        with open(pid_file, 'rb') as f:
            pid = int(f.read())
        time.sleep(args.wait)
        subprocess.check_output('kill -10 {}'.format(pid).encode(), shell=True)
        sys.exit()
    path = os.path.abspath(os.path.expanduser(args.file))
    if not os.path.exists(path):
        print("No vault file at {} -- initializing empty vault".format(args.file))
    args.path = path
    if not args.password:
        msg = "Password for {}: ".format(args.file)
        if not os.path.exists(path):
            args.password = set_password_dialog(msg)
        else:
            args.password = getpass.getpass(msg)
    return args


def main():
    signal.signal(signal.SIGINT, lambda *a: sys.exit(1))
    args = parse_args()
    vault = Vault(path=args.path, password=args.password)
    signal.signal(signal.SIGUSR1, output_password)
    print(intro_msg)
    with open(pid_file, 'w') as f:
        f.write(str(os.getpid()))
    while True:
        print("command: \rcommand: ", end='')
        i, o, e = select.select([sys.stdin], [], [], args.timeout)
        if not i:
            timeout_loop(vault)
            continue
        user_input = sys.stdin.readline().strip()
        if not user_input:
            continue
        execute_command(vault, user_input)


if __name__ == '__main__':
    main()
