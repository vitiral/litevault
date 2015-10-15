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
keypress_delay_us = '10000'

##################################################
# Constants

pid_file = '/tmp/litevault.pid'
intro_msg = r'''
 ************************************
 *       /-------\  Type "?" or "h" *
 *  lite | vault |     for help.    *
 *       \-------/                  *
 ************************************'''
help_msg = '''\
Help:
h or ?         = help
q or exit      = quit litevault
L              = lock litevault (same as if it timed out)
s or save      = save vault state to disk)
n              = set new password for vault (and save it to disk)
t              = set new timeout password
l or ls     [] = list items. Add an item to do a fuzzy search
c or mk     [] = create/overwrite item in vault  * (in memory. Use 's' to save changes to file)
d or rm     [] = delete data from vault          * (in memory, use 's' to save changes to file)
u           [] = get user
p           [] = get password
i           [] = get info
a           [] = get user + password and show info
[NON-MATCHING] = same as "a [NON-MATCHING]". Happens when item doesn't match any commands
'''
TIMEOUT_PWD_KEY='__litevault_timeout_password__'


##################################################
# X keboard automation mappings
# http://www.linux.org/threads/xdotool-keyboard.6414/

x_char_mappings = {
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


def send_keypresses(characters, delay_us=10000):
    '''Send a sequence of keypresses to the keyboard.

    This function is intended to be secure -- as in outside processes should not be
    able to see what it is doing.

    :characters: characters to send
    :delay_us: delay in microseconds between each keypress
    '''
    k = '\nusleep {}\nkey '.format(delay_us)
    keypresses = (c if c not in x_char_mappings else x_char_mappings[c]
                  for c in characters)
    keypresses = ('key ' + k.join(keypresses) + '\n').encode()
    sh = subprocess.Popen(['xte'], stdin=subprocess.PIPE)
    sh.communicate(input=keypresses)


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


def clear_screen(wait=True):
    out = ''
    if wait:
        if wait is True:
            wait = '\n ** Press ENTER to clear the screen **'
        out = input(wait)
    print('\x1b[0;0H\x1b[2J\n' + intro_msg)
    return out


def output_password(signum, stack):
    '''Output the password on the keyboard'''
    if not curpass:
        return
    send_keypresses(curpass, keypress_delay_us)


def verify_environment():
    requirements = {
        "xautomation: need xte": 'xte -h',
    }
    for r, cmd in requirements.items():
        try:
            subprocess.check_output(cmd.encode().split())
        except Exception as E:
            quit_app('!! Dependency not met: {} !!'.format(r), rc=1)


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


def quit_app(msg=None, rc=0):
    print(msg or " ** Quitting litevault **")
    sys.exit(rc)


##################################################
# Vault Class

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
        text = scrypt.decrypt(encrypted, self.password, maxtime=self.maxtime * 20)
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
    newpass = set_password_dialog("Enter new vault password: ")
    if not newpass:
        print("No password entered, skipping")
        return
    vault.save()
    vault.password = newpass
    vault.save()
    print("Vault with new password saved")


def set_timeout_pwd(vault, *args):
    tpass = set_password_dialog("Enter new timeout password: ")
    if not tpass:
        print("No password entered, doing nothing.")
        return
    vault[TIMEOUT_PWD_KEY] = tpass
    print("New timeout password saved")


# Other User Functions

def execute_command(vault, user_input):
    print_help = lambda vault, item: print(help_msg)
    interface = {
        # global actions
        '?': print_help,    'h': print_help,
        'q': quit_app,      'exit': quit_app,
        's': save_vault,    'save': save_vault,
        'n': new_password,
        't': set_timeout_pwd,
        'L': lambda vault, item: timeout_loop(vault, locked=True),
        # actions on items
        'l': list_items,    'ls': list_items,
        'c': create_item,   'mk': create_item,
        'd': delete_item,   'rm': delete_item,
        'u': load_user,
        'p': load_password,
        'i': load_info,
        'a': load_all,
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


def timeout_loop(vault, locked=False):
    global curpass
    curpass = ''
    clear_screen(False)
    if locked:
        print(" ** litevault locked. Buffered password cleared    **")
    else:
        print(' ** litevault timed out. Buffered password cleared **')
    print(" ** 's' will still save and 'q' will quit          ** ")
    timeout_pwd = vault.get(TIMEOUT_PWD_KEY)
    msg = "Enter vault password: " if not timeout_pwd else "Enter vault or timeout password: "
    for n in range(3):
        pwd = getpass.getpass(msg)
        if pwd == 'q':
            quit_app()
        elif pwd == 's':
            save_vault()
            continue
        if pwd == vault.password or pwd == timeout_pwd:
            return
        time.sleep(1)
        print("!! Incorrect password attempt {} out of 3 !!".format(n+1))
    quit_app("!! Incorrect password 3 times, exiting !!", rc=1)


##################################################
# App Functions

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--send_stored_pass', action='store_true')
    parser.add_argument('-w', '--wait', default=0.25, help="Wait time before sending the stored password")
    parser.add_argument('-p', '--password', help='Use only in testing, not secure!')
    parser.add_argument('-f', '--file', default='~/.vault',
                        help='password file to load. Default is ~/.vault')
    parser.add_argument('-t', '--timeout', default=300, type=float,
                        help='time in seconds before program is locked with no activity (default=300)')
    parser.add_argument('-k', '--keypress_delay_us', default=10000, type=int,
                        help='time in micro-seconds to delay between each keypress when entering passwords')
    parser.add_argument('--test', action='store_true', help='used for testing')
    args = parser.parse_args()
    verify_environment()
    if args.send_stored_pass:
        with open(pid_file, 'rb') as f:
            pid = int(f.read())
        time.sleep(args.wait)
        subprocess.check_output('kill -10 {}'.format(pid).encode(), shell=True)
        sys.exit()
    global keypress_delay_us
    keypress_delay_us = args.keypress_delay_us
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
    signal.signal(signal.SIGINT, lambda *a: quit_app(" ** Received Cntrl+C, quitting **"))
    args = parse_args()
    vault = Vault(path=args.path, password=args.password)
    signal.signal(signal.SIGUSR1, output_password)
    with open(pid_file, 'w') as f:
        f.write(str(os.getpid()))
    if args.test:
        load_password(vault, 'hello')
        output_password(None, None)
        return
    print(intro_msg)
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
