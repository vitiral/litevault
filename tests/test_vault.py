import json
import tempfile
from unittest import TestCase

from litevault import Vault

passwords = {
    'citi': {
        'u': 'mynameisbob',
        'p': 'save me charlie 43',
        'i': 'this is a bank',
    },
    'gmail': {
        'u': 'user@gmail.com',
        'p': 'the best password',
        'i': 'my email! whooo!',
    },
}

class TestVault(TestCase):
    def test_load_dump(self):
        with tempfile.NamedTemporaryFile('wb+') as f:
            vault = Vault(f.name, 'hello', maxtime=0.1, initial_data=passwords)
            assert vault == passwords

            # data not actually saved yet. Save it and reload it
            vault.save()
            vault._load_passwords()
            assert vault == passwords

            # Make sure that data is jumbled
            f.seek(0)
            encrypted = f.read()
            with self.assertRaises(UnicodeDecodeError):
                encrypted.decode()
