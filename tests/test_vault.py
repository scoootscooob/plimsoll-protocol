"""Tests for the Key Vault (Context-Window Airgap)."""

from plimsoll.enclave.vault import KeyVault


def test_store_and_sign():
    vault = KeyVault()
    vault.store("wallet_1", "supersecretkey")
    sig = vault.sign("wallet_1", b"hello world")
    assert isinstance(sig, str)
    assert len(sig) == 64  # SHA256 hex digest


def test_deterministic_signatures():
    vault = KeyVault()
    vault.store("k", "key")
    sig1 = vault.sign("k", b"msg")
    sig2 = vault.sign("k", b"msg")
    assert sig1 == sig2


def test_different_messages_different_sigs():
    vault = KeyVault()
    vault.store("k", "key")
    sig1 = vault.sign("k", b"msg1")
    sig2 = vault.sign("k", b"msg2")
    assert sig1 != sig2


def test_sign_transaction():
    vault = KeyVault()
    vault.store("agent", "secret")
    sig = vault.sign_transaction("agent", {"to": "0xABC", "value": 100})
    assert len(sig) == 64


def test_list_key_ids():
    vault = KeyVault()
    vault.store("a", "secret_a")
    vault.store("b", "secret_b")
    ids = vault.list_key_ids()
    assert set(ids) == {"a", "b"}


def test_has_key():
    vault = KeyVault()
    assert not vault.has_key("x")
    vault.store("x", "val")
    assert vault.has_key("x")


def test_destroy_key():
    vault = KeyVault()
    vault.store("temp", "data")
    vault.destroy("temp")
    assert not vault.has_key("temp")


def test_sign_eth_transaction():
    """Vault can ECDSA-sign an Ethereum transaction (context-window airgap)."""
    from eth_account import Account as EthAccount
    from web3 import Web3

    # Generate a real Ethereum keypair
    acct = EthAccount.create()
    private_key_hex = acct.key.hex()

    vault = KeyVault()
    vault.store("eth_wallet", private_key_hex)

    # Build a minimal valid Ethereum transaction dict (checksummed address)
    recipient = EthAccount.create().address
    tx_dict = {
        "to": Web3.to_checksum_address(recipient),
        "value": 1000,
        "gas": 21000,
        "maxFeePerGas": 50000000000,
        "maxPriorityFeePerGas": 2000000000,
        "nonce": 0,
        "chainId": 11155111,  # Sepolia
        "type": 2,
    }

    raw_tx = vault.sign_eth_transaction("eth_wallet", tx_dict)
    assert isinstance(raw_tx, bytes)
    assert len(raw_tx) > 0

    # Verify the signer matches our account
    recovered = EthAccount.recover_transaction(raw_tx)
    assert recovered.lower() == acct.address.lower()


def test_raw_secret_never_exposed():
    """The vault API has no method to retrieve the raw secret."""
    vault = KeyVault()
    vault.store("private", "0xDEADBEEF" * 8)

    # No get/retrieve/export method exists
    assert not hasattr(vault, "get")
    assert not hasattr(vault, "retrieve")
    assert not hasattr(vault, "export")
    assert not hasattr(vault, "decrypt")

    # Only key_ids are listed, never values
    assert "private" in vault.list_key_ids()
