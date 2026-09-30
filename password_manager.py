import os
import json
import base64
import getpass
import secrets
import string
from pathlib import Path

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


VAULT_FILE = Path("vault.enc")
SALT_FILE = Path("salt.bin")


def derive_key(master_password: str, salt: bytes) -> bytes:
    """Dérive une clé AES-256 à partir du mot de passe maître."""
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1
    )
    return kdf.derive(master_password.encode("utf-8"))


def get_or_create_salt() -> bytes:
    if SALT_FILE.exists():
        return SALT_FILE.read_bytes()

    salt = os.urandom(16)
    SALT_FILE.write_bytes(salt)
    return salt


def encrypt_vault(data: dict, key: bytes) -> bytes:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    ciphertext = aes.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ciphertext)


def decrypt_vault(key: bytes) -> dict:
    if not VAULT_FILE.exists():
        return {}

    try:
        raw = base64.b64decode(VAULT_FILE.read_bytes())
        nonce = raw[:12]
        ciphertext = raw[12:]
        aes = AESGCM(key)
        plaintext = aes.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode("utf-8"))
    except Exception:
        print("\n❌ Clé maître incorrecte ou coffre corrompu.")
        raise SystemExit(1)


def save_vault(vault: dict, key: bytes) -> None:
    encrypted = encrypt_vault(vault, key)
    VAULT_FILE.write_bytes(encrypted)


def generate_password(length: int = 20) -> str:
    if length < 12:
        length = 12

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)
            and any(c.isdigit() for c in password)
            and any(c in "!@#$%^&*()-_=+" for c in password)
        ):
            return password


def add_password(vault: dict, key: bytes) -> None:
    print("\n--- Ajouter un compte ---")
    website = input("Site / Application : ").strip()
    username = input("Identifiant : ").strip()

    if not website:
        print("❌ Le nom du site ne peut pas être vide.")
        return

    choice = input("Générer automatiquement un mot de passe ? (o/n) : ").strip().lower()

    if choice == "o":
        try:
            length = int(input("Longueur [20] : ").strip() or "20")
        except ValueError:
            length = 20

        password = generate_password(length)
        print(f"\n🔐 Mot de passe généré : {password}")
    else:
        password = getpass.getpass("Mot de passe : ")

    vault[website] = {
        "username": username,
        "password": password
    }

    save_vault(vault, key)
    print("✅ Compte enregistré et chiffré.")


def show_password(vault: dict) -> None:
    if not vault:
        print("\nAucun compte enregistré.")
        return

    website = input("\nNom du site : ").strip()

    account = vault.get(website)

    if not account:
        print("❌ Compte introuvable.")
        return

    print(f"\nSite : {website}")
    print(f"Identifiant : {account['username']}")
    print(f"Mot de passe : {account['password']}")


def list_accounts(vault: dict) -> None:
    print("\n--- Comptes enregistrés ---")

    if not vault:
        print("Aucun compte.")
        return

    for website, account in sorted(vault.items()):
        print(f"- {website} → {account['username']}")


def search_accounts(vault: dict) -> None:
    if not vault:
        print("\nAucun compte enregistré.")
        return

    query = input("\nRecherche : ").strip().lower()

    results = [
        (website, account)
        for website, account in vault.items()
        if query in website.lower() or query in account["username"].lower()
    ]

    if not results:
        print("❌ Aucun résultat.")
        return

    print("\n--- Résultats ---")
    for website, account in sorted(results):
        print(f"- {website} → {account['username']}")


def delete_password(vault: dict, key: bytes) -> None:
    website = input("\nCompte à supprimer : ").strip()

    if website not in vault:
        print("❌ Compte introuvable.")
        return

    confirm = input(f"Confirmer la suppression de '{website}' ? (o/n) : ").strip().lower()

    if confirm != "o":
        print("Suppression annulée.")
        return

    del vault[website]
    save_vault(vault, key)
    print("✅ Compte supprimé.")


def change_master_password(vault: dict, current_salt: bytes) -> tuple[bytes, bytes]:
    print("\n--- Changer la clé maître ---")

    new_master = getpass.getpass("Nouvelle clé maître : ")
    confirm = getpass.getpass("Confirmer la nouvelle clé : ")

    if new_master != confirm:
        print("❌ Les deux clés ne correspondent pas.")
        return derive_key(new_master, current_salt), current_salt

    if len(new_master) < 12:
        print("❌ Utilise au moins 12 caractères.")
        return derive_key(new_master, current_salt), current_salt

    new_salt = os.urandom(16)
    new_key = derive_key(new_master, new_salt)

    SALT_FILE.write_bytes(new_salt)
    save_vault(vault, new_key)

    print("✅ Clé maître modifiée.")
    return new_key, new_salt


def first_run_setup() -> str:
    print("\nPremière utilisation : crée ta clé maître.")
    while True:
        master = getpass.getpass("Nouvelle clé maître : ")
        confirm = getpass.getpass("Confirmer : ")

        if master != confirm:
            print("❌ Les deux clés ne correspondent pas.\n")
            continue

        if len(master) < 12:
            print("❌ Utilise au moins 12 caractères.\n")
            continue

        return master


def main() -> None:
    print("""
=========================================
       GESTIONNAIRE DE MOTS DE PASSE
=========================================
AES-256-GCM + Scrypt
""")

    is_first_run = not SALT_FILE.exists() and not VAULT_FILE.exists()

    if is_first_run:
        master_password = first_run_setup()
    else:
        master_password = getpass.getpass("🔑 Clé maître : ")

    salt = get_or_create_salt()
    key = derive_key(master_password, salt)
    vault = decrypt_vault(key)

    if is_first_run:
        save_vault(vault, key)
        print("\n✅ Coffre créé.")

    while True:
        print("""
-----------------------------
1 - Ajouter un mot de passe
2 - Afficher un mot de passe
3 - Lister les comptes
4 - Rechercher
5 - Générer un mot de passe
6 - Supprimer un compte
7 - Changer la clé maître
8 - Quitter
-----------------------------
""")

        choice = input("Choix : ").strip()

        if choice == "1":
            add_password(vault, key)

        elif choice == "2":
            show_password(vault)

        elif choice == "3":
            list_accounts(vault)

        elif choice == "4":
            search_accounts(vault)

        elif choice == "5":
            try:
                length = int(input("Longueur [20] : ").strip() or "20")
            except ValueError:
                length = 20
            print(f"\n🔐 {generate_password(length)}")

        elif choice == "6":
            delete_password(vault, key)

        elif choice == "7":
            old_key = key
            new_master = getpass.getpass("Nouvelle clé maître : ")
            confirm = getpass.getpass("Confirmer la nouvelle clé : ")

            if new_master != confirm:
                print("❌ Les deux clés ne correspondent pas.")
                continue

            if len(new_master) < 12:
                print("❌ Utilise au moins 12 caractères.")
                continue

            new_salt = os.urandom(16)
            new_key = derive_key(new_master, new_salt)

            SALT_FILE.write_bytes(new_salt)
            save_vault(vault, new_key)

            key = new_key
            salt = new_salt
            print("✅ Clé maître modifiée.")

        elif choice == "8":
            print("\n🔒 Coffre fermé.")
            break

        else:
            print("❌ Choix invalide.")


if __name__ == "__main__":
    main()
