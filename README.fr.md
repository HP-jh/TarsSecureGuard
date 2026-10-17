🌐 **Langues**: [🇨🇳 简体中文](README.md) · [🇺🇸 English](README.en.md) · [🇷🇺 Русский](README.ru.md) · [🇸🇦 العربية](README.ar.md) · [🇫🇷 Français](README.fr.md) · [🇯🇵 日本語](README.ja.md) · [🇰🇷 한국어](README.ko.md)

---

<div align="center">

# 🛡️ TarsSecureGuard

### Le routeur et le configurateur de l'ère de l'IA —— Le routeur et le configurateur de l'ère de l'IA, avec ceinture de sécurité intégrée

<p>
<b>Utilisable directement après décompression</b> · <b>Haute sécurité</b> · <b>Aucune configuration requise</b> · <b>Compatible avec toutes les plateformes</b> · <b>Connecte tout</b> · <b>Configure pour vous les autres outils d'IA</b>
</p>

<p>
Une <b>passerelle IA locale</b> sans dépendance, en fichier unique et purement statique : elle connecte à gauche 13 types de clients logiciels d'IA (Claude Desktop / Cursor / Cline / Continue / Windsurf / Codex CLI / Warp / Cody / JetBrains / Tabnine / Zed / Roo Code / VS Code Copilot),<br/>
se connecte à droite à <b>24 fournisseurs de modèles cloud + 8 environnements d'inférence locaux</b> (OpenAI / Anthropic / Gemini / DeepSeek / Tongyi / Wenxin / GLM / Doubao / Kimi / MiniMax / Hunyuan / Xinghuo / Groq / Ollama / LM Studio / vLLM …),<br/>
active au milieu obligatoirement le WAF, la protection sémantique, la limitation de débit hiérarchique, la réputation IP, le RBAC, l'audit et la désensibilisation des PII —— <b>Plus vous connectez de services, plus vous devez être protégé</b>.
</p>

<p>
<b>Pas seulement une passerelle, mais aussi un configurateur (v4.11.0 Extender)</b> : La configuration de l'environnement des autres outils d'IA est fastidieuse ? TSG les configure pour vous à l'envers —— Le détecteur intégré scanne les <b>OpenClaw / Continue / Aider / Cline / ZooCode / Codex CLI</b> déjà installés sur votre machine,
génère en un clic le fragment de configuration d'accès qui pointe l'outil vers le point de terminaison TSG (la clé peut être intégrée et auditée tout au long du processus), il suffit de copier-coller pour terminer. Toutes les cibles font partie de l'écosystème MIT / Apache, <b>aucune pollution GPL, aucune dépendance externe</b>.
</p>

<p>
<img alt="Version" src="https://img.shields.io/badge/version-4.11.0-success">
<img alt="Go" src="https://img.shields.io/badge/Go-1.22.8-00ADD8?logo=go&logoColor=white">
<img alt="Deps" src="https://img.shields.io/badge/dependencies-0-brightgreen">
<img alt="Providers" src="https://img.shields.io/badge/providers-13clients%C3%9724cloud-blue">
<img alt="Platforms" src="https://img.shields.io/badge/platforms-7%20native%20targets-blueviolet">
<img alt="MCP" src="https://img.shields.io/badge/MCP-stdio%20%2B%20HTTP%20%2B%20auto--include-22d3ee">
<img alt="Tests" src="https://img.shields.io/badge/tests-race%20green">
<img alt="License" src="https://img.shields.io/badge/license-MIT-orange">
</p>

</div>

---

## 📣 Message de recommandation

> **Lorsque chaque client d'IA dispose de sa propre écosystème de modèles privé, TarsSecureGuard vous permet de connecter tous les modèles, tous les outils et tous les protocoles avec une seule clé compatible OpenAI —— et ce, avec une ceinture de sécurité obligatoire.**
>
> Téléchargez un archive compressée, décompressez-la, double-cliquez dessus —— le service démarre sur le port local `18889` et le panneau d'administration en chinois s'ouvre automatiquement dans le navigateur. Ce n'est pas une nouvelle "passerelle lourde" qui vous oblige à tirer une image de 1 Go et à installer MySQL, mais une passerelle de sécurité **sans dépendance, purement statique, qui fonctionne même si vous la copiez sur une clé USB**.
>
> La version v4.11.0 pousse la "connexion" à l'extrême —— **Une seule clé d'abonnement Coding Plan ouvre tous les modèles** ; la feuille de route de 50 intégrations est déjà établie ; trois modes d'intégration : open source / closed source / CLI (**embed intégration / federate fédération / wrap-cli-as-mcp empaquetage**) ; pour les services qui ne peuvent pas être connectés temporairement, vous recevez une liste de connexion exécutable.
>
> Alors que d'autres passerelles vous obligent encore à configurer des fichiers YAML et à déboguer les règles de routage, TarsSecureGuard a déjà attaché votre ceinture de sécurité, connecté les clients et vous a remis la clé en main.

---

## 🌟 Message de présentation

TarsSecureGuard est une **passerelle IA privilégiant le fonctionnement local (local-first) —— le routeur de l'ère de l'IA**. Il se situe entre vous et toutes les capacités d'IA : à gauche se trouvent vos logiciels d'IA (Claude Desktop, Cursor, Cline, Windsurf, Codex CLI … au choix), à droite se trouvent 24 fournisseurs de modèles cloud + 8 environnements d'inférence locaux (connexion au choix) ; il expose un point de terminaison compatible OpenAI (HTTP ou **stdio**) + MCP vers l'extérieur, et assure l'orchestration, la gouvernance et l'audit unifiés à l'intérieur.

> Le routeur chez vous ne produit pas de câbles réseau ni de sites web —— il permet à chaque appareil de naviguer sur Internet en toute sécurité. TarsSecureGuard ne produit pas de modèles et ne vous oblige pas à utiliser un client particulier —— **Il permet à chaque client d'IA d'utiliser chaque modèle en toute sécurité.** Nous prévoyons de pousser cette mission à l'extrême : connecter ce qui peut être connecté, et pour ce qui ne peut pas l'être temporairement, vous fournir une liste de connexion exécutable (voir `docs/v3.2.0-unconnectable.md`).

### Nouveauté de la v4.11.0 · Feuille de route du Connecteur Universel

> **Une seule clé d'abonnement Coding Plan = la clé de tous les modèles**. TSG cache les différences entre les fournisseurs derrière la couche de compatibilité OpenAI, les clients d'IA n'ont pas besoin d'être réécrits et les utilisateurs n'ont pas besoin de changer d'outil.

Intégrer tous les logiciels d'IA du monde (y compris les outils open source / closed source / CLI qui ne peuvent pas être connectés directement) dans TSG, trois **modes d'intégration** :

| Mode | Objet applicable | Méthode |
|---|---|---|
| **embed (intégration)** | Bibliothèques open source (C/C++/Go/Rust/Python) | Compiler le code dans le processus TSG et l'appeler directement (comme ggml / whisper.cpp / sqlite-vec) |
| **federate (fédération)** | Services distants / passerelles API | Orchestration unifiée via le proxy inverse TSG + adaptation de protocole (tous les hubs MCP, plates-formes API tierces) |
| **wrap-cli-as-mcp (empaqueter CLI en MCP)** | Tout outil en ligne de commande | Empaquetage sans code en serveur MCP, l'IA l'appelle indirectement via TSG (comme ripgrep / fd / magika / jq) |

**Progrès actuel** : 24 fournisseurs cloud + 8 environnements locaux (enregistrement intégré, un fichier lisible par machine par fournisseur), guides d'intégration de 13 clients, liste de 17 éléments temporairement non connectables (objectif de 50 intégrations pour la v3.3.0). **L'ajout d'un nouveau fournisseur ne nécessite que l'écriture de configuration, pas de modification du code** —— c'est pourquoi la v4.11.0 peut assumer le rôle de "routeur".

### Cinq caractéristiques principales

| Caractéristique | Description |
|------|------|
| 🔌 **Connecte tout** | Registre des fournisseurs de la v4.11.0 : enregistrement intégré de 24 fournisseurs cloud + 8 environnements locaux (un fichier lisible par machine par fournisseur), guides d'intégration de 13 types de clients d'IA ; l'ajout d'un nouveau fournisseur **ne nécessite que l'écriture de configuration, pas de modification du code**. |
| 📦 **Utilisable directement après décompression** | Aucune installation, aucun conteneur, aucune base de données requise. Décompressez l'archive, double-cliquez sur `start.bat` / `start.sh`, le service démarre immédiatement et le panneau d'administration en chinois s'ouvre automatiquement dans le navigateur. |
| 🔒 **Haute sécurité** | Noyau de sécurité chargé obligatoirement, **impossible à désactiver** : WAF (traversée de chemin / injection de commande / SQLi / XSS / **injection de Prompt** / **détection de PII**), **routage hiérarchique par détection sémantique (échec-fermeture)** , **limitation de débit à trois dimensions par seau à jetons**, **notation de réputation IP locale**, trois rôles RBAC, audit structuré, désensibilisation des PII, cinq lignes rouges SSRF, liaison à trois niveaux du pare-feu. Peu importe l'étendue des connexions, la chaîne de sécurité ne sera jamais affaiblie. |
| 🚀 **Performances optimales** | Pool de connexions partagé (taux de réutilisation mesuré à 98,5 %), coupure de circuit et dégradation des fournisseurs, cache à deux niveaux (adaptation de protocole + cache de réponse isolé par locataire) ; la latence P99 des requêtes sortantes est **réduite de 27 % à 40 %** par rapport à la base de référence de la v3.0.x (le benchmark reproductible est fourni avec le code source, voir `docs/v3.2.0-performance.md` pour plus de détails). |
| 💻 **Bonne compatibilité environnementale** | Un seul code source, des binaires pour six plateformes (macOS Intel/Apple Silicon, Linux x86_64/ARM64, Windows x64/ARM64) ; purement statique avec `CGO_ENABLED=0`, fonctionne immédiatement après copie sur d'anciens noyaux, d'anciennes distributions ou des réseaux intranet isolés. |

### 💎 Version d'abonnement (Subscription)

> **La version communautaire est entièrement gratuite et open source (MIT) ; la version d'abonnement est destinée aux utilisateurs qui souhaitent "économiser du temps + être conformes + bénéficier de mises à jour continues".**

| Fonctionnalité | Version communautaire (gratuite) | **Version d'abonnement (recommandée)** |
|------|:---:|:---:|
| Passerelle / modèles locaux et cloud / WAF / protection sémantique / limitation de débit / réputation IP / RBAC / audit | ✅ | ✅ |
| Gardien de ressources / routage intelligent / notation des modèles / MCP stdio | ✅ | ✅ |
| Binaires pour six architectures sur toutes les plateformes | ✅ | ✅ |
| **Paquets de mise à jour en un clic** (construction automatique de la dernière version sur le cloud, pas de manipulation manuelle) | — | ✅ |
| **Mises à jour continues de la base de règles de sécurité** (dernières caractéristiques d'injection de Prompt / de jailbreak, stratégies de réputation IP) | Rythme de la communauté | **Mises à jour prioritaires** |
| **Importation de données d'évaluation hors ligne lm-eval et recommandations d'optimisation** | Manuel | ✅ Optimisation par des experts |
| Support de déploiement conformes pour la privatisation / l'intranet | — | ✅ |
| Support technique d'usine et SLA | — | ✅ |

L'abonnement vous donne droit à **des mises à jour continues de la protection de sécurité et à une livraison sans souci** : vous n'avez qu'à décompresser et utiliser, la protection, la stabilité et la compatibilité sont garanties en permanence par l'abonnement.

---

## 🧩 Aperçu des fonctionnalités de la v3.0.0 ("Votre ceinture de sécurité pour l'IA")

### Ligne A · Gardien de ressources (resourceGuardian)
- Limite de mémoire souple `GOMEMLIMIT` (min(10 % de la mémoire physique, 384 Mo), 128 Mo en mode éco, modifiable).
- **Réponses hiérarchisées L0–L3** : L1 dégradation des services non essentiels → L2 coupure de circuit des services à haute consommation → L3 arrêt gracieux (drainage de 30s + écriture des audits sur disque + sauvegarde de l'état + code de sortie 42 + refroidissement pour éviter les tempêtes).
- Les niveaux L2/L3 sont déterminés selon **la mesure RSS**, pour détecter les fuites de mémoire CGO / externes ; le mode éco d'économie de ressources s'applique automatiquement au matériel de catégorie D.

### Ligne B · Mise à niveau de la protection
- **Routage hiérarchique par détection sémantique (semanticGuard)** : Les règles statiques sont appliquées en premier, les zones grises sont envoyées à un petit modèle local de 0,5B–1,5B pour jugement ; **règle impérative d'échec-fermeture** —— si le moteur est indisponible, une erreur 503 est renvoyée directement, aucune requête n'est autorisée ; cache des empreintes digitales + limite de débit pour les zones grises.
- **Limitation de débit à trois dimensions par seau à jetons (rateLimiter)** : IP×type de point de terminaison / Clé×type de point de terminaison / Total par IP, dépassement renvoie une erreur 429 et déclenche une déduction de points de réputation.
- **Réputation IP locale (ipReputation)** : Score initial de 100, des points sont déduits en cas de déclenchement du WAF / de scan / de dépassement de limite, les adresses à faible score sont automatiquement bannies, gestion des listes blanches, récupération automatique après 24h, alerte sur anomalie NAT, déblocage par l'administrateur.
- Règle impérative de fusion unidirectionnelle « **L'IA ne peut que renforcer la sécurité** » : Les stratégies de sécurité ne peuvent que devenir plus strictes, 100 % de tests unitaires + audit à l'exécution.

### Ligne C · Routage intelligent à deux phases
- **smartRouter** : Les règles statiques sont prioritaires comme filet de sécurité + **bandit ε-greedy** (ε décroît de 0,1 à 0,02), sélection automatique du backend optimal selon l'historique de taux de réussite / de latence ; les retours des utilisateurs non administrateurs sont pondérés moins fort pour éviter les falsifications.
- **scoreBoard** : Les scores d'exécution (taux de réussite × latence) sont fusionnés avec les évaluations hors ligne **lm-eval-harness** (référence relative, annotation honnête ; sidecar Python disponible à la demande, pas de dépendance obligatoire).

### Ligne D · Élévation de la niche écologique
- **`--mcp-stdio` : JSON-RPC 2.0 sur stdio**, tout agent local accède à l'ensemble des protections dès sa connexion —— la différenciation clé de cette version.
- Outils : `tars_guarded_chat` / `tars_guard_status` / `tars_route_preview` / `tars_model_score` / `tars_module_schema` / `tars_ip_reputation_unban` ; les opérations d'administration nécessitent la clé `TSG_ADMIN_KEY` et sont entièrement auditées.

### Ligne E · Ingénierie de la stabilité
- Récupération de panique sur tous les chemins ; Go fuzzing (WAF / analyse de configuration / normalisation sémantique) ; **Script de test de charge de 8 heures** (`soak.sh` / `soak.ps1`) ; tous les tests unitaires et d'intégration httptest avec l'option `-race` sont passés.

### Plateforme et livraison
- Interface utilisateur entièrement en chinois ; **Fichiers de déploiement complets** : unité systemd, Dockerfile, docker-compose (rootless), exemple de sidecar K8s, LaunchDaemon macOS (voir le dossier [`deploy/`](./deploy)).
- Aucune dépendance tierce dans `go.mod`, uniquement la bibliothèque standard —— **Aucune surface d'attaque par la chaîne d'approvisionnement**.

---

## 🏗️ Architecture

```
                 ┌──────────────────────────────────────────────────┐
 OpenAI SDK /    │         Noyau de Sécurité (obligatoire·indésactivable)        │
 Agent local ───▶ │ WAF → Routage sémantique → Limitation de débit → Réputation IP → RBAC → Audit → PII │
 (HTTP / stdio)  └─────────────────────────┬────────────────────────┘
                                           │
                    ┌──────────────────────┴───────────────────────┐
                    │   Routage intelligent à deux phases (règles statiques + bandit ε-greedy)  │
                    └──────────────────────┬───────────────────────┘
        ┌────────────┬────────────┬─────────┴────────┬────────────┬────────────┐
        ▼            ▼            ▼                  ▼            ▼            ▼
   GGUF local      LM Studio    Ollama            Modèles cloud    Outils/MCP     Gardien de ressources
  (llama.cpp)     :1234        :11434         OpenAI/DeepSeek  Recherche/capture    L0-L3/Notation
```

---


### Capacités avancées v4.11+

- **🖥️ Client bureau Tauri** : barre système permanente + fenêtre de démarrage + privilèges admin + auto-mise à jour + WebSocket + 7 plateformes
- **🔌 Pont MCP auto-include** : une ligne dans `config.json` pour monter automatiquement les serveurs MCP externes
- **🖱️ Contrôle de bureau ByteDance UI-TARS** : intègre UI-TARS-1.5-7B / Doubao vision, l'IA contrôle le bureau via MCP
- **🛡️ 360 Security UI** : navigation gauche + panneau droit, style 360 Security Guard
- **🧠 Routage multi-appareils LobeHub** : collaboration multi-agent
- **📊 Tableau de bord utilisation Token** : statistiques par fournisseur / app / jour
- **🔑 Système de clés virtuelles vKey** : clés virtuelles indépendantes avec quota et audit
- **🎯 Stratégie de routage modèles** : requêtes simples → petits modèles, complexes → grands modèles

## 🚀 Démarrage rapide

### Installation en un clic (recommandé, détecte automatiquement le système et l'architecture)
```sh
# macOS / Linux
curl -fsSL https://raw.githubusercontent.com/HP-jh/TarsSecureGuard/main/install.sh | sh
```
```powershell
# Windows PowerShell
irm https://raw.githubusercontent.com/HP-jh/TarsSecureGuard/main/install.ps1 | iex
```
Après installation, exécutez `tsg` pour démarrer la passerelle, le panneau s'ouvre automatiquement à l'adresse `http://127.0.0.1:18889` ; exécutez `tsg doctor` pour effectuer un auto-test de l'environnement. Vous pouvez également télécharger le paquet d'installation unifié `tsg-setup.zip` (contient l'installateur pour toutes les plateformes, s'adapte automatiquement après exécution).

### Exécution depuis le code source
```sh
git clone https://github.com/HP-jh/TarsSecureGuard && cd TarsSecureGuard
go run .          # ou ./start.sh (double-cliquez sur start.bat sur Windows)
```

### Site officiel de référence
Site web léger (aperçu des fonctionnalités / installation en un clic / jalons de version / FAQ) : `site/index.html`, utilisable immédiatement après activation de GitHub Pages (Paramètres → Pages → branche main / dossier `site`).

### Mise à niveau de l'interface utilisateur (v3.2.4)
**Visualisation frontale de la couche de gouvernance** : Ajout d'un groupe de navigation « Gouvernance » dans la barre latérale, les quatre pages : vue d'ensemble de la gouvernance (agrégation de la gouvernance + état OAuth) / mémoire partagée / informations partagées / chaîne d'audit v2 sont toutes connectées à l'API réelle —— auparavant, les 8 points de terminaison REST de gouvernance n'étaient pas accessibles depuis le front et ne pouvaient être appelés que par curl. L'exportation des audits se fait via un téléchargement de blob avec un en-tête d'authentification (la clé n'apparaît pas dans l'URL) ; correction également du décalage du badge de version de la barre latérale présent depuis la v3.2.2. Tous les tests de bout en bout sans tête Playwright + Chromium sont passés, le front n'a aucun privilège, la visibilité sur les audits est préservée. Voir [docs/v3.2.4-ui.md](./docs/v3.2.4-ui.md) pour plus de détails.

### Mise à niveau des performances v2 (v3.2.3)
**Fusion des regex WAF en un seul passage + présélection par octet de déclenchement ASCII** (une seule regex fusionnée par mode normal/strict pour un filtrage rapide en un seul passage, le nom de la règle est récupéré en cas de correspondance, aucun changement sémantique ; les textes entièrement en chinois sont exemptés de regex, le scan strict est réduit de 99,8 %), **désensibilisation des PII en un seul passage** (fusion des quatre modes en un seul remplacement, réduction de 15 %), **verrou à 16 fragments pour le cache de réponse** (découpage fixe par FNV-1a, mutex + LRU indépendants, réduction de 10 % des opérations get/put concurrentes sur 2 cœurs) —— les candidats ont été examinés et validés un par un : exclusion du sync.Pool JSON et du commit par lot des audits (l'ordre d'écriture est l'ordre de la chaîne de hachage, la modification asynchrone présente un risque de rupture de chaîne), invalidation du chemin SSE (il n'existe pas dans le code). Voir [docs/v3.2.3-performance.md](./docs/v3.2.3-performance.md) pour plus de détails.

### Couche de gouvernance + mise à niveau des performances v1 (v3.2.2)
**Mémoire partagée** (trois espaces de noms : utilisateur → locataire → global, chaîne de résolution avec écrasement par proximité, l'isolation des locataires est garantie par la normalisation des espaces de noms), **Informations partagées** (entrées de connaissances structurées : fait/préférence/note/lien + recherche par poids), **MCP d'extension de contexte** (assemblage de l'identité et des stratégies + des informations partagées + de la mémoire partagée en un paquet de contexte déterministe, le contenu injecté et l'entrée utilisateur passent par la même chaîne de sécurité), **Intégration de l'IdP entreprise OAuth/OIDC** (Code d'autorisation + PKCE, vérification de signature RS256/ES256 écrite manuellement avec la bibliothèque standard, échec-fermeture, les sessions utilisent la même matrice RBAC que les utilisateurs locaux), **Gardien de porte** (ligne de défense au niveau des actions avant l'exécution des outils : interdiction de modifier la configuration de sécurité, interdiction d'accéder aux chemins sensibles, confirmation à deux phases pour les opérations à haut risque, prévention de la falsification de l'identité, configuration en mode renforcement seulement), **Audit à chaîne de hachage v2** (SHA256 entre les blocs consécutifs, rotation des fichiers par jour, reprise de la chaîne après redémarrage, recalcul de la chaîne entière pour prévenir la falsification) —— voir [docs/v3.2.2-governance.md](./docs/v3.2.2-governance.md) pour plus de détails. Il y a également la **mise à niveau des performances v1** : pipeline de gestion des descripteurs de fichiers de logs ouverts en permanence (réduction de 79 % du temps d'écriture des lignes sur disque), complétion de la couverture du pool de connexions (pooling pour les détections de doctor / alignement des paramètres de customToolClient avec préservation de l'isolation SSRF), précompilation des regex tier 1 au niveau du paquet —— voir [docs/v3.2.2-performance.md](./docs/v3.2.2-performance.md) pour plus de détails.

### Client de bureau (ajouté dans la v3.2.1, ne dépend pas du navigateur)
Téléchargez le paquet d'installation depuis la page [Release](../../releases) (Windows `.exe` / macOS `.dmg` / Linux `.deb`·`.AppImage`) → Double-cliquez pour installer → La console d'administration en chinois s'ouvre directement dans une **fenêtre native**, aucun navigateur n'est ouvert tout au long du processus. Le sidecar de la passerelle est automatiquement lancé dans le wrapper, il s'arrête lorsque vous fermez la fenêtre, aucun processus résiduel ; les données sont stockées dans le répertoire des données utilisateur du système. Voir [docs/v3.2.1-desktop-client.md](./docs/v3.2.1-desktop-client.md) pour plus de détails.

### Intégration MCP stdio (différenciation clé)
```sh
./tarssecureguard --mcp-stdio
# Dans un agent local prenant en charge MCP stdio, enregistrez cette commande en tant que serveur MCP,
# Vous obtiendrez automatiquement l'ensemble des outils protégés comme tars_guarded_chat.
```

### Construction depuis le code source (six plateformes)
```sh
GOOS=linux  GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=3.0.0" -o tarssecureguard .
go test -race ./...      # Tests unitaires + tests d'intégration
./soak.sh                # Test de charge de stabilité de 8 heures (optionnel)
```
Les commandes complètes de construction pour les six plateformes et la matrice des systèmes minimaux sont disponibles dans [COMPATIBILITY.md](./COMPATIBILITY.md).

> Port d'administration par défaut `18889`, port des modèles locaux `18890` ; Clé API par défaut `tars-gateway-key`, veuillez la modifier dans `config.json` ou l'injecter via la variable d'environnement `TARS_API_KEY` ; les opérations d'administration peuvent utiliser la clé `TSG_ADMIN_KEY`.

---

## 🖥️ Matrice de compatibilité multi-plateformes

| Plateforme | Système minimal | État |
|------|----------|:---:|
| macOS Intel (amd64) | macOS 10.15 Catalina | ✅ |
| macOS Apple Silicon (arm64) | macOS 11 Big Sur | ✅ |
| Linux x86_64 | Noyau 2.6.32+ (purement statique) | ✅ |
| Linux ARM64 | Noyau 2.632+ (statique pur) | ✅ |
| Windows x64 | Windows 10 / 11 | ✅ |
| Windows ARM64 | Windows 10/11 sur ARM | ⚠️ Expérimental |

Pour plus de détails, consultez [COMPATIBILITY.md](./COMPATIBILITY.md).

---

## 🥊 Analyse des principaux concurrents

**Conclusion : Le concurrent le plus important et auquel il faut répondre de front est actuellement LiteLLM** (standard de fait des passerelles AI open source, environ 60 000 étoiles, écosystème et notoriété les plus forts) ; sur le marché chinois, **New API / One API** est le leader de notoriété sur la voie Go ; sur le positionnement « priorité locale », **OmniRoute** est le plus proche.

| Concurrent | Avantages | Faiblesses par rapport à TarsSecureGuard |
|------------|-----------|------------------------------------------|
| **LiteLLM** (concurrent principal) | Couverture de fournisseurs la plus large, écosystème mature, clés virtuelles/budget/réessai complets, première notoriété à l'étranger | Stack technique Python, déploiement lourd (nécessite Postgres + Redis, image de plus de 500 Mo, ensemble proche de 1 Go) ; centré sur les modèles cloud ; la sécurité n'est pas un argument de vente par défaut ; pas de fichier unique prêt à l'emploi après décompression ; pas de fermeture par défaut en cas d'échec sémantique / de守护 de ressources |
| **New API / One API** (notoriété en Chine) | Écrit en Go, modèles chinois complets, chaîne opérationnelle de distribution/jeton/facturation/recharge complète | Positionné sur la « revente API / facturation opérationnelle », nécessite MySQL + Redis ; paramètres nombreux et complexes ; pas conçu pour les modèles locaux / les scénarios de sécurité sur machine unique |
| **OmniRoute** (priorité locale) | Positionnement clair « local-first », croissance rapide des étoiles, dégradation automatique et stratégies de routage multiples | Orienté « routage d'agrégation de fournisseurs multiples », la gouvernance de sécurité (WAF/sémantique/RBAC/limitation de débit/réputation IP/audit/PII) n'est pas au cœur du produit ; le fichier unique sans dépendance et la conformité intranet ne sont pas ses arguments |
| **LM Studio / Ollama + OpenWebUI** (alternatives « suffisantes ») | Déjà installé par les utilisateurs, interface GUI conviviale, découverte de modèles pratique | Ce sont des **environnements d'exécution** et non des passerelles de gouvernance : ils ne fournissent pas de WAF, de protection sémantique, de limitation de débit, de réputation IP, de RBAC, d'audit, de守护 de ressources — TarsSecureGuard vient justement gérer et compléter cette couche |

**Stratégie de différenciation : Ne pas concurrencer sur le « nombre de fournisseurs », mais occuper la niche écologique négligée et extrêmement douloureuse pour les particuliers et les intranets — « **Configuration zéro + fichier unique + sécurité activée par défaut + priorité locale + protection plug-and-play via stdio** ». Les passerelles lourdes servent les grandes entreprises disposant d'équipes plateformes ; TarsSecureGuard sert les particuliers, les geeks et les intranets isolés qui veulent « utiliser l'IA locale de manière sûre et stable dès aujourd'hui ».

---

## 🏰 Analyse du fossé de protection le plus profond

**Conclusion : Le fossé de protection le plus profond est l'actif de confiance accumulé par « Security Core » et la base de connaissances de défense de la sécurité LLM, renforcé en continu par l'ingénierie de surface d'attaque nulle du « fichier unique sans dépendance » ; le MCP stdio de la version 3.0 permet à cette protection de se distribuer automatiquement avec l'intégration, élargissant davantage le fossé.**

Le fossé est divisé en trois couches, de la plus superficielle à la plus profonde :

1. **Couche de simplicité technique (facile à copier, avantage à court terme)** : Aucune dépendance tierce, fichier unique statique pur, support de six plateformes,守护 de ressources et routage intelligent. Les concurrents peuvent l'imiter, mais cela nécessite une retenue à long terme et un abandon de l'écosystème — ce que la plupart des équipes ne parviennent pas à faire.

2. **Couche de connaissances en sécurité (barrière centrale, rendement composé dans le temps)** : Security Core est un ensemble complet d'**actifs de défense dédiés aux LLM** — WAF et signatures d'injection de Prompt/de jailbreak, jugement de zone grise sémantique (fermeture par défaut en cas d'échec), empreintes de comportement de réputation IP, limitation de débit tridimensionnelle, modèles PII et anonymisation, cinq lignes rouges SSRF, interconnexion avec les pare-feu, système d'audit, et optimisation continue du ratio « taux de détection vs taux de faux positifs ». **Plus il y a d'échantillons réels → plus les règles sont précises → moins il y a de faux positifs → plus il y a d'utilisateurs → plus il y a d'échantillons**, une roue d'auto-renforcement que les nouveaux venus ne peuvent pas compenser en copiant le code une seule fois.

3. **Couche de confiance et de distribution (la plus profonde, la plus difficile à copier)** : La barrière finale des produits de sécurité est le **registre de confiance « jamais eu d'incident »** et la notoriété en matière de conformité ; l'engagement de conception « la sécurité ne peut jamais être désactivée / l'IA ne peut que devenir plus stricte » se transforme en choix par défaut. La **protection plug-and-play via stdio** de la version 3.0 signifie que tout agent local hérite de l'ensemble de la protection dès son intégration — la capacité de protection se diffuse automatiquement avec l'intégration, formant une **roue de distribution**. La version d'abonnement monétise la confiance par des mises à jour de sécurité continues et un SLA. La confiance ne peut pas être établie en un trimestre, ni détruite par une guerre des prix.

> **Jugement honnête** : Le projet est en phase de croissance, son fossé de protection est toujours en « élargissement » — il peut être copié au niveau des fonctionnalités. Sa véritable largeur est déterminée par **les données de défense apportées par l'adoption + la roue de distribution stdio + le registre de confiance à long terme sans incident**. La valeur stratégique de la version d'abonnement est précisément de transformer les « mises à jour de sécurité continues » en un actif à rendement composé, facturable et accumulant de la confiance.

---

## 📚 Documentation

- [CHANGES.md](./CHANGES.md) —— Modifications complètes de chaque version (y compris la mise à niveau UI de la v3.2.4, la mise à niveau des performances v2 de la v3.2.3, la mise à niveau de la couche de gouvernance + des performances v1 de la v3.2.2, le client bureau de la v3.2.1, la version majeure de connectivité de la v4.11.0)
- [docs/v3.2.4-ui.md](./docs/v3.2.4-ui.md) —— **Mise à niveau UI** : Quatre pages de visualisation de la couche de gouvernance / correction des interactions / validation de bout en bout Playwright
- [docs/v3.2.3-performance.md](./docs/v3.2.3-performance.md) —— **Mise à niveau des performances v2** : Fusion en un seul passage + présélection WAF / traitement en un seul passage PII / verrou par fragment de cache de réponse / référence A-B
- [docs/v3.2.2-governance.md](./docs/v3.2.2-governance.md) —— **Couche de gouvernance** : Mémoire partagée / informations partagées / extension de contexte MCP / OAuth/IdP / gardien / mise à niveau de l'audit
- [docs/v3.2.2-performance.md](./docs/v3.2.2-performance.md) —— **Mise à niveau des performances v1** : Pipeline de gestion de descripteurs de fichiers pour les logs toujours ouverts / complétion de la couverture du pool de connexions / référence A-B
- [docs/v3.2.1-desktop-client.md](./docs/v3.2.1-desktop-client.md) —— **Client bureau** : Décisions de conception de l'enveloppe Tauri, construction et recette
- [docs/v3.2.0-connectivity.md](./docs/v3.2.0-connectivity.md) —— **Guide de connexion** : Intégration de 13 clients AI + 24 fournisseurs cloud + 8 environnements d'exécution locaux
- [docs/v3.2.0-performance.md](./docs/v3.2.0-performance.md) —— **Référence de performances** : P99 / taux de réutilisation des connexions / taux de succès du cache (reproductible)
- [docs/v3.2.0-unconnectable.md](./docs/v3.2.0-unconnectable.md) —— **Liste des connexions temporairement impossibles** : 16 éléments + brouillon de schéma d'intégration par fournisseur
- [COMPATIBILITY.md](./COMPATIBILITY.md) —— Matrice de compatibilité multiplateforme et guide de construction
- [OPTIMIZATION_REPORT.md](./OPTIMIZATION_REPORT.md) —— Rapport d'optimisation et feuille de route technique
- [deploy/](./deploy) —— Fichiers de déploiement systemd / Docker / docker-compose / K8s / LaunchDaemon

## 📄 Licence

[Licence MIT](./LICENSE) —— Utilisation, modification et partage libres.

<div align="center">

🛡️ **TarsSecureGuard —— Votre ceinture de sécurité pour l'IA. Prêt à l'emploi après décompression, sécurité permanente.**

</div>
