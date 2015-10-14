
from litevault import Vault

def test_vault():
    vault = Vault('hi.aes', 'password')
    v = vault.get_vault()
    v['bob'] = 'joe'
    vault.store_vault(v)
    v2 = vault.get_vault()
    assert v == v2
