<p align="center">
  <a href="README.ja.md">日本語</a> | <a href="README.zh.md">中文</a> | <a href="README.es.md">Español</a> | <a href="README.md">English</a> | <a href="README.hi.md">हिन्दी</a> | <a href="README.it.md">Italiano</a> | <a href="README.pt-BR.md">Português (BR)</a>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/mcp-tool-shop-org/brand/main/logos/nullout/readme.png" width="400" alt="NullOut">
</p>

<p align="center">
  <a href="https://github.com/mcp-tool-shop-org/nullout/actions/workflows/ci.yml"><img src="https://github.com/mcp-tool-shop-org/nullout/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://codecov.io/gh/mcp-tool-shop-org/nullout"><img src="https://codecov.io/gh/mcp-tool-shop-org/nullout/branch/main/graph/badge.svg" alt="Coverage"></a>
  <a href="https://github.com/mcp-tool-shop-org/nullout/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT License"></a>
  <a href="https://mcp-tool-shop-org.github.io/nullout/"><img src="https://img.shields.io/badge/Landing_Page-live-blue" alt="Landing Page"></a>
</p>

Un serveur MCP qui détecte et supprime en toute sécurité les fichiers "indélébiles" sous Windows.

Windows réserve des noms de périphériques tels que `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9` et `LPT1`-`LPT9` au niveau de Win32. Les fichiers portant ces noms peuvent exister sur NTFS (créés via WSL, des outils Linux ou des API de bas niveau), mais ils deviennent impossibles à renommer, déplacer ou supprimer via l'Explorateur ou les commandes shell classiques.

NullOut analyse ces entrées potentiellement dangereuses et les supprime en toute sécurité en utilisant l'espace de noms de chemin étendu `\\?\`, avec un flux de travail de confirmation en deux phases conçu pour les serveurs MCP.

## Fonctionnement

1. **Analyse** des répertoires autorisés pour détecter les conflits de noms réservés, les points/espaces à la fin des noms et les chemins trop longs.
2. **Planification** de la suppression : NullOut génère un jeton de confirmation unique pour chaque fichier, lié à son identité (numéro de série du volume + identifiant du fichier).
3. **Suppression** avec le jeton : NullOut vérifie que le fichier n'a pas été modifié (protection TOCTOU) avant de le supprimer via l'espace de noms étendu.

## Modèle de sécurité

- **Uniquement les racines autorisées** : les opérations sont limitées aux répertoires que vous configurez explicitement.
- **Pas de chemins bruts dans les opérations destructives** : la fonction de suppression n'accepte que les identifiants de fichier et les jetons de confirmation émis par le serveur.
- **Politique de refus de tous les points de réanalyse (`deny_all`)** : les jonctions, les liens symboliques et les points de montage ne sont jamais parcourus ni supprimés.
- **Liaison de l'identité du fichier** : les jetons sont signés par HMAC et liés au numéro de série du volume + à l'identifiant du fichier ; toute modification entre l'analyse et la suppression est rejetée.
- **Uniquement les répertoires vides** : la version 1 refuse de supprimer les répertoires non vides.
- **Erreurs structurées** : chaque échec renvoie un code lisible par machine avec des suggestions pour la prochaine étape.

## Outils MCP

| Outil | Type | Fonction |
|------|------|---------|
| `list_allowed_roots` | lecture seule | Afficher les racines d'analyse configurées. |
| `scan_reserved_names` | lecture seule | Rechercher les entrées dangereuses dans une racine. |
| `get_finding` | lecture seule | Obtenir les détails complets d'une entrée détectée. |
| `plan_cleanup` | lecture seule | Générer un plan de suppression avec des jetons de confirmation. |
| `delete_entry` | destructif | Supprimer un fichier ou un répertoire vide (nécessite un jeton). |
| `who_is_using` | lecture seule | Identifier les processus qui verrouillent un fichier (Gestionnaire de redémarrage). |
| `get_server_info` | lecture seule | Métadonnées du serveur, politiques et capacités. |

## Configuration

Définir les racines autorisées via une variable d'environnement :

```
NULLOUT_ROOTS=C:\Users\me\Downloads;C:\temp\cleanup
```

Secret de signature des jetons (générer une valeur aléatoire) :

```
NULLOUT_TOKEN_SECRET=your-random-secret-here
```

## Modèle de menace

NullOut protège contre :

- **Utilisation abusive destructrice** : la suppression nécessite un jeton de confirmation émis par le serveur ; aucun chemin brut n'est accepté.
- **Parcours de chemin** : toutes les opérations sont limitées aux racines autorisées ; les séquences `..` sont résolues et rejetées.
- **Échappement des points de réanalyse** : les jonctions, les liens symboliques et les points de montage ne sont jamais parcourus ni supprimés (`deny_all`).
- **Courses TOCTOU** : les jetons sont liés par HMAC au numéro de série du volume + à l'identifiant du fichier ; toute modification de l'identité entre l'analyse et la suppression est rejetée.
- **Astuces d'espace de noms** : les opérations destructives utilisent le préfixe de chemin étendu `\\?\` pour contourner l'analyse de nom Win32.
- **Fichiers verrouillés** : l'attribution du Gestionnaire de redémarrage est en lecture seule ; NullOut ne tue jamais de processus.
- **Répertoires non vides** : refusés par la politique ; seuls les répertoires vides peuvent être supprimés.

**Données consultées :** métadonnées du système de fichiers (noms, identifiants de fichiers, numéros de série des volumes), métadonnées des processus (PIDs, noms d'applications via le Gestionnaire de redémarrage).
**Données NON consultées :** contenu des fichiers, réseau, informations d'identification, registre Windows.
**Aucune télémétrie** n'est collectée ou envoyée.

## Prérequis

- Windows 10/11
- Python 3.10+

---

Créé par <a href="https://mcp-tool-shop.github.io/">MCP Tool Shop</a>
