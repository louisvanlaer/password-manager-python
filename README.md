# Gestionnaire de mots de passe Python

Petit gestionnaire de mots de passe local en Python.

## Fonctionnalités

- Coffre chiffré avec AES-256-GCM
- Clé dérivée avec Scrypt
- Ajout de comptes
- Affichage d'un mot de passe
- Recherche par site ou identifiant
- Générateur de mots de passe sécurisé
- Suppression de comptes
- Changement de clé maître
- Aucun mot de passe stocké en clair sur le disque

## Installation

```bash
pip install -r requirements.txt
```

## Lancer le projet

```bash
python password_manager.py
```

## Fichiers créés automatiquement

Après le premier lancement :

- `vault.enc` : coffre chiffré
- `salt.bin` : sel utilisé pour dériver la clé

Ne publie jamais ton vrai `vault.enc` sur GitHub.

## Sécurité

La clé maître n'est pas sauvegardée.

Si tu la perds, il n'existe pas de fonction permettant de récupérer les mots de passe.

Pour un usage réel contenant des mots de passe importants, préfère un gestionnaire audité comme Bitwarden, 1Password ou KeePassXC. Ce projet reste surtout pédagogique.
