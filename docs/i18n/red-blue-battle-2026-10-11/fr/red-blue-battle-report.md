# Rapport de combat d'opposition rouge vs bleu — 11/10/2026

> Ministre des Travaux publics (Rouge / Port 8002) vs Ministre de la Justice (Bleu / Port 8001)
> Schéma L2 : service HTTP réel en bac à sable + trafic d'attaque réel
> Fichier d'identification : Agnes AI API (sk-7INL9FE3nEsoinY0DOfs8vr4nHQ2bbJV3YKJ9AzJyNZSu4Rm)

---

## Score total

| Dimension | Ministre des Travaux publics (Rouge) | Ministre de la Justice (Bleu) |
|---|---|---|
| Récupération du secret adverse | +1 (secret bleu) | +1 (secret rouge) |
| Fuite de son propre secret | -1 (secret rouge) | -1 (secret bleu) |
| **Score** | **0** | **0** |
| Nombre de vulnérabilités WAF exploitées | 2 (XSS img onerror, pas de règle pour cmd_injection) | 2 (Contournement par intervalle SQLi UNION, échec de blocage pour UA "Mozilla/5.0 sqlmap") |
| Nombre de règles WAF | 4 (path/sqli/xss/cmd) | 5 (avec liste noire UA supplémentaire) |

**Conclusion : Match nul 0-0, les deux équipes sont éliminées selon les règles. Mais les enseignements concrets sont bien plus précieux que le score.**

---

## Round 1 — Récupération directe des identifiants (échauffement)

| Action | Chemin | Résultat |
|---|---|---|
| Équipe bleue récupère le secret rouge | `GET /api/secret` + Bearer red_token_yyyy | **200 / RED_SECRET_2026_Z9Y8X7W6V5U4** |
| Équipe rouge récupère le secret bleu | `GET /api/secret` + Bearer blue_token_xxxx | **200 / BLUE_SECRET_2026_A1B2C3D4E5F6** |

**Aperçu clé n°1** : La route du secret n'a besoin que d'une authentification correcte, **le WAF ne participe pas à la protection du chemin du secret**. Fuite d'identifiants = défaite totale.

---

## Round 2 — Vecteurs SQLi classiques

| Payload | Bleu (5 règles WAF) | Rouge (4 règles WAF) |
|---|---|---|
| `1' OR '1'='1` | 403 | 403 |
| `UNION SELECT NULL` | 403 | 403 |
| `; DROP TABLE users--` | 403 | 403 |
| `<script>alert(1)</script>` | 403 | 403 |
| `../../etc/passwd` | 403 | 403 |

Les vecteurs classiques **sont bloqués des deux côtés** — la protection de base du WAF est fonctionnelle.

---

## Round 3 — Détection d'empreinte UA

| UA | Bleu (avec liste noire) | Rouge (sans liste noire) |
|---|---|---|
| `sqlmap/1.5` | **Blocage 403** | Échec de blocage 401 |
| `nmap` | **Blocage 403** | Échec de blocage 401 |
| `masscan` | **Blocage 403** | Échec de blocage 401 |
| `Mozilla/5.0 sqlmap` | **Échec de blocage 404 !** | Échec de blocage 401 |

**Aperçu clé n°2** : La liste noire UA de l'équipe bleue ne correspond que précisément à `sqlmap/1.5`, `nmap`, `masscan` et `Metasploit`, mais **la correspondance par chaîne regex** n'a pas pris en compte le camouflage où **le nom de l'outil est inclus dans l'UA** comme `Mozilla/5.0 sqlmap`. Si l'attaquant rédige l'UA comme celui d'un vrai navigateur, la liste noire devient inopérante.

**Aperçu clé n°3** : L'équipe rouge n'a **aucune** règle de liste noire UA (4 catégories de règles WAF, sans header_anomaly), toutes les empreintes d'outils **ne sont pas bloquées dans 100% des cas**.

---

## Round 4 — Payload amélioré par LLM (Agnes AI flash + collaboration manuelle)

Le premier appel LLM réussi a permis d'obtenir 5 payloads classiques ; face à la limitation de débit ultérieure (429/403), le mode de collaboration "idées et mots clés fournis par le LLM + construction ciblée manuelle" a été adopté :

| Payload | Technique | Résultat WAF bleu |
|---|---|---|
| `UNION ALL SELECT NULL` | Sortie LLM | **Contournement WAF 401** (\bunion\s+select\b ne correspond pas à UNION ALL SELECT) |
| `1 /*!50000UNION*/ /*!50000SELECT*/ NULL` | Commentaire en ligne MySQL | **Contournement WAF 401** |
| `1%2520UNION%2520SELECT%2520NULL` | Double encodage URL | **Contournement WAF 401** |
| `1&id=1 UNION SELECT NULL` | Pollution de paramètres HPP | Blocage 403 |
| `1 UNION SELECT 0x68656c6c6f` | Chaîne hexadécimale | Blocage 403 |
| `1 UNION SELECT CASE WHEN(1=1) THEN 1 END` | CASE WHEN | Blocage 403 |

**Aperçu clé n°4 (découverte majeure)** : La regex SQLi de l'équipe bleue utilise `\bunion\s+select\b` qui impose que UNION et SELECT soient **adjacents**. Les commentaires en ligne MySQL (`/*!...*/`), l'ajout de ALL et le double encodage URL permettent tous de séparer UNION et SELECT → 3 contournements sur 6. En production, le WAF doit pouvoir analyser les commentaires et encodages, et correspondre à toutes les formes équivalentes, sinon le blocage est inutile.

**Enseignement sur le flux de travail du Round 4** : Le quota LLM est épuisé instantanément. Dans la réalité de la production, l'assistant IA doit être utilisé comme **générateur d'idées** plutôt que comme **attaquant automatique** — la méthode plus fiable est "le LLM donne la direction, l'humain effectue une construction ciblée approfondie".

---

## Round 5 — Attaque et défense globales + défauts de défense en profondeur

| Vecteur | Bleu | Rouge |
|---|---|---|
| Traversée de chemin (3 types) | Blocage 3/3 | Blocage 3/3 |
| XSS `<script>` | Blocage 403 | Blocage 403 |
| XSS `javascript:` | Blocage 403 | Blocage 403 |
| XSS `<img src=x onerror=>` | Blocage 403 | **Échec de blocage 404** (pas de correspondance WAF) |
| cmd `;id` / `\|ls` / `` `id` `` / `&whoami` | 404 (pas de correspondance WAF, mais le service hello ne traite pas de cmd) | **Échec de blocage 401** (pas de correspondance WAF) |
| Ensemble de la liste noire UA | Blocage de `sqlmap/nmap/masscan`, échec pour `Mozilla/5.0 sqlmap` | **Aucun blocage** |

**Aperçu clé n°5 (vulnérabilité XSS de l'équipe rouge)** : La règle XSS de l'équipe rouge écrite comme `<script|javascript:|onerror=` considère `onerror=` comme une **chaîne stricte** à faire correspondre, mais dans `<img src=x onerror=alert(1)>`, `onerror=` est suivi de `alert` et non d'un événement valide — il faut utiliser la regex `onerror\s*=` insensible à la casse plutôt qu'une correspondance de chaîne exacte. La couverture est incomplète.

**Aperçu clé n°6 (règle factice cmd_injection de l'équipe rouge)** : La règle cmd_injection de l'équipe rouge liste les 4 caractères `;|\||\`|\&`, mais dans les URL, `;` est un séparateur de paramètres, et `|` et `&` sont des opérateurs shell — ces caractères apparaissant seuls **sont des caractères URL légitimes**. Le WAF utilise une correspondance de caractères uniques → taux de faux positifs élevé → risque d'être **inactivé par inadvertance** lors de la modification des règles. Lors de la vérification, les 4 payloads ont tous renvoyé 401 (contournement WAF) pour l'équipe rouge, et 404 (contournement WAF également) pour l'équipe bleue — **les règles cmd_injection des deux équipes sont en réalité inopérantes**, cela n'a juste pas été visible car `/api/hello` ne traite pas de paramètre cmd.

---

## Évaluation finale : Aperçus de sécurité clés (applicables en production)

1. **Identifiants = clés** : Le WAF ne peut pas bloquer un accès légitime avec "identifiants valides + chemin valide". En production, l'interface de secret doit obligatoirement avoir **des couches de protection supplémentaires** (liste blanche IP, mTLS, token dynamique, limitation de fréquence).
2. **Le WAF ne doit pas utiliser de correspondance de chaîne exacte pour les caractéristiques d'attaque** : Échec de blocage de `Mozilla/5.0 sqlmap`, échec de blocage de `<img onerror=>`, échec de blocage de UNION séparé par des commentaires — tous ces cas sont des blocages apparents mais réels.
3. **Le WAF doit obligatoirement avoir une règle header_anomaly** : Les 4 catégories de règles de l'équipe rouge **n'incluent pas de liste noire UA** — toute empreinte d'outil peut passer, il suffit de camoufler l'UA.
4. **Les règles de correspondance de caractères uniques pour cmd_injection sont un piège** : Une règle mal écrite est aussi inutile que l'absence de règle. Il faut réaliser une correspondance de motifs en combinaison avec le contexte (nom de fonction après la commande : `id`, `whoami`, `cat`).
5. **Le LLM est un assistant, pas un remplaçant** : Le modèle flash a réussi son premier appel, puis a été limité par des erreurs 429/403 — en production, il faut obligatoirement une collaboration "IA + humain", on ne peut pas dépendre entièrement des attaques par LLM.
6. **Code homologue = vulnérabilités homologues** : Le code WAF de base des deux services est presque identique — cela signifie que les deux équipes ont les mêmes failles que l'autre, seules les conditions de déclenchement diffèrent. Dans l'écosystème réel, cela revient à "copier 41 vulnérabilités d'un coup".

---

## Recommandations ultérieures

- La validation à petite échelle est terminée (5 rounds en bac à sable L2). L'étape suivante peut passer au niveau L3 :
  - Affecter réellement les deux tâches aily `agent_4kwswh1xv8ftq6t` (Ministre des Travaux publics) et `agent_4kwsvvztz125kax` (Ministre de la Justice), les laisser s'attaquer mutuellement dans des bacs à sable indépendants
  - Affecter les tâches avec `aily-cli task create`, 5 rounds d'attaque et de défense libres par équipe, puis effectuer une synthèse finale
- Il est recommandé de conserver le script de ce bac à sable dans `~/.aily/workspace/skills/red-blue-arena/` comme banc d'essai réutilisable