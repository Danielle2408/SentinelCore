# Préparer l’IA locale de SentinelCore

## Objectif

L’IA locale est l’analyste principal des alertes non triviales : elle rapproche les signaux D1/D2, formule la conclusion et propose le plan. D3 reste le garde-fou : il vérifie les permissions et n’exécute que les actions typées déjà présentes dans son catalogue. Les règles déterministes servent au repli si Ollama est indisponible et aux cas critiques explicitement définis.

Exemple : D2 signale une activité automatisée inhabituelle; D1 indique un écart avec les habitudes, alors que l’application et l’heure semblent familières. L’IA compare les faits, explique les hypothèses, puis peut demander un contexte précis à D1 ou D2. Après la réponse, elle rend son verdict final. D3 vérifie que toute mesure demandée est autorisée par le catalogue et les permissions.

## Simulation de fonctionnement

1. D1 et D2 envoient leurs messages à D3 selon le protocole inter-démons. L’IA ne se connecte jamais directement à D1 ou D2.
2. D3 valide les messages, associe leurs `correlationId`, puis crée un résumé minimal. Les messages et textes libres sont des données non fiables.
3. D3 envoie les constats techniques D2, les écarts comportementaux D1 et le contexte agrégé à l’IA pour les cas non triviaux. Un cas critique défini par la politique peut recevoir une mesure immédiate.
4. D3 appelle `IAmbiguousCaseAdvisor.AnalyzeAsync`. Le client envoie une requête HTTP JSON non-streamée à Ollama sur `http://127.0.0.1:11434/api/chat`, avec `gemma3:1b` par défaut. Le menu permet de choisir un autre modèle déjà installé.
5. Le modèle rend une conclusion, sa confiance, les faits et hypothèses, les incertitudes, une mesure typée, les demandes de contexte et, si nécessaire, `capabilityGap` avec un `playbookDraft` non exécutable. Les champs d’analyse sont dimensionnés pour détailler les cas complexes; le modèle n’est pas réduit à un simple choix de règle.
6. Le code C# vérifie de nouveau la réponse. Une mesure inconnue, une demande non autorisée, une preuve inventée, un champ supplémentaire, un JSON incomplet ou trop gros invalide l’avis.
7. Si le modèle demande un contexte, D3 vérifie la liste autorisée, l’envoie à D1 ou D2, puis attend la réponse sous le même identifiant de corrélation.
8. À chaque réponse, D3 transmet les nouveaux faits à l’IA. La boucle compte au plus trois analyses; l’avis précédent évite de repartir de zéro. Une demande en attente bloque l’action jusqu’à la nouvelle analyse.
9. Une réponse IA valide fixe le risque et le plan proposés. D3 ne remplace pas ce risque par son moteur de règles; il vérifie séparément les limites d’action (par exemple, un scan Defender requiert un constat D2 et l’accord du propriétaire en mode réel). Une réponse IA invalide ou indisponible déclenche le repli déterministe.
10. Chaque avis, demande, verdict et résultat d’action est conservé dans le rapport. Un `playbookDraft` peut inclure un brouillon PowerShell de diagnostic en lecture seule; il reste du texte inerte pour examen. Aucun texte du modèle ne devient une commande exécutée. Pour activer ensuite une nouvelle capacité, un développeur doit l’implémenter, la tester et l’ajouter explicitement au catalogue D3.

## Échange entre les composants

| Liaison | Moyen prévu | Données échangées |
|---|---|---|
| D1/D2 → D3 | Named Pipes Windows, protocole versionné et adapté aux formats d’ACK propres à chaque client | Enveloppes `USER_CONTEXT`, `BEHAVIOR_DEVIATION`, `THREAT_FINDING`, `TELEMETRY_GAP` et réponses de contexte autorisées |
| D3 → IA | Appel HTTP local à Ollama, boucle locale seulement | Objet `AmbiguousSecurityCase` minimisé; jamais les enveloppes brutes |
| IA → D3 | Réponse JSON vérifiée par `OllamaAmbiguousCaseAdvisor` | conclusion, plan typé, questions de contexte et playbook facultatif non exécutable |
| D3 → D1 après conseil | Named Pipe Windows, demandes D1 typées | Uniquement les demandes autorisées dans ce cas |
| D3 → D2 | Named Pipe duplex avec enveloppe versionnée | Demande de détails limitée aux constats, règles, types de preuves et télémétrie manquante du dossier concerné |
| D3 → action | Politique locale puis catalogue interne typé | Identifiant d’action pré-approuvé, jamais une commande construite par l’IA |

Ollama est limité à une adresse IP de boucle locale en HTTP. Le client refuse les adresses réseau distantes. Le service Ollama doit rester local et ne doit pas être exposé au réseau. Le transport inter-démons et le canal duplex D2 sont implémentés; les ACL pour comptes de service et la déduplication durable restent à renforcer.

## Entrées autorisées à l’IA

`AmbiguousSecurityCase` accepte un identifiant de corrélation, au plus 20 signaux résumés et au plus trois types de demandes de contexte déjà autorisés. Chaque signal doit venir d’un démon connu et employer un type de message reconnu. Les résumés sont courts; les références sont des identifiants techniques.

À ne pas transmettre : frappes clavier, mots de passe, secrets, texte intégral d’une page, commande ou script, ligne de commande d’un processus, chemin complet, nom d’utilisateur, photo/vidéo, modèle biométrique ou empreinte faciale. D1 fournit des écarts agrégés, des plages d’heures, des catégories d’usage applicatif et des bandes CPU/mémoire; un nom de programme éventuel est réduit au seul nom du processus. D2 fournit les règles, niveaux, confiance, types de preuves, faits catégoriels et catégories de télémétrie manquante.

Les résumés de D1/D2 peuvent contenir des instructions malveillantes. Le prompt les traite explicitement comme des données, mais ce rappel ne constitue pas une protection suffisante à lui seul : la protection réelle repose sur l’absence d’outils, les listes fermées, les limites de taille et la validation déterministe après génération.

## Sortie autorisée

- `riskBand`: `LOW`, `GUARDED`, `ELEVATED`, `HIGH`, `CRITICAL` ou `UNCERTAIN`.
- `suggestedMeasure`: une valeur fermée comme `CONTINUE_MONITORING`, `REQUEST_D1_CONTEXT`, `REQUEST_OWNER_CONFIRMATION`, `RUN_DEFENDER_QUICK_SCAN`, `CONTAINMENT_REVIEW`, `CAPABILITY_GAP` ou `NO_RECOMMENDATION`.
- `requestedContext`: zéro à trois valeurs autorisées par D3 pour ce cas.
- `summary` et `rationale`: texte bref destiné à l’analyse et au rapport; il n’est jamais exécuté.
- `evidenceRefs`: références reprises à l’identique depuis l’entrée.
- `capabilityGap`: description de la capacité absente si la mesure vaut `CAPABILITY_GAP`.
- `playbookDraft`: brouillon borné d’une procédure, éventuellement d’un diagnostic en lecture seule, conservé comme texte non exécutable.

L’avis IA ne déclare pas, à lui seul, une identité vérifiée. D3 n’accepte jamais le texte du playbook comme action; seules les actions explicitement programmées et typées peuvent passer au catalogue. En cas d’indisponibilité, timeout ou réponse IA invalide, le statut est enregistré et D3 reprend le repli déterministe défini par la politique.

## État du code dans cette étape

Déjà présent :

- contrats `AmbiguousSecurityCase`, `SecuritySignalSummary`, `RiskAdvice` et `AdvisorOutcome`;
- interface `IAmbiguousCaseAdvisor` pour ne pas coupler l’orchestrateur à un fournisseur;
- client `OllamaAmbiguousCaseAdvisor` limité à la boucle locale, avec timeout, taille de réponse bornée, température zéro et sortie JSON Schema;
- validation des catégories, types de messages, demandes de contexte, champs inattendus et références de preuve;
- option CLI `--ollama-advisory-demo` qui envoie des signaux synthétiques et n’effectue aucune action système; analyse locale structurée depuis l’orchestrateur, verdict IA sauvegardé, contexte D1/D2 demandé selon le besoin, cycle borné à trois analyses et actions typées uniquement.

État et travaux restants :

1. Enrichir les 50 scénarios SQLite avec une conclusion de référence pour mesurer risques, demandes de contexte et faux positifs/faux négatifs; la base sert à évaluer le comportement, pas à entraîner directement Ollama.
2. Renforcer les ACL de Named Pipes pour l’exécution en service, la déduplication durable et la reprise après redémarrage.
3. Mesurer précision et latence dans un benchmark reproductible avant de déclarer un modèle apte à une décision autonome.
4. Annoter les 50 scénarios avec une conclusion de référence, puis mesurer précision, demandes de contexte, faux positifs/faux négatifs et latence avant de déclarer un modèle apte à une décision autonome.

## Modèle candidat et essais

Le modèle par défaut est `gemma3:1b`, avec boucle locale `127.0.0.1`, contexte de 4 096 jetons, jusqu’à 1 800 jetons générés et délai de 120 secondes. Le client sérialise les options Ollama sous leurs noms d’API (`num_ctx`, `num_predict`, `keep_alive`) et les tests inspectent ce JSON. Le centre permet de choisir un modèle déjà présent avec une taille locale positive; les noms `:cloud` et `-cloud` sont rejetés avant tout appel d’inférence. La connexion au compte Ollama/Google ne redirige pas une requête locale vers le cloud.

Mesures comparatives initiales du 21 novembre 2026 sur un cas synthétique identique, avec une machine CPU-only :

- `gemma3:1b` : avis accepté en 9,8 s, mais réponse en anglais, confiance 0,98 non étayée, hypothèse d’exfiltration sans preuve réseau et aucune demande de contexte alors que D1/D2 sont autorisés. Il est rapide, mais le verdict brut n’est pas fiable.
- `gemma2:2b` : 43,8 s; réponse rejetée par D3 (`OLLAMA_UNSUPPORTED_VISUAL_INFERENCE`) après une interprétation qui contredit `visualStatus=NOT_REQUESTED`.
- `gemma3:4b` : délai expiré à 120 s; l’essai a également rencontré des erreurs d’allocation mémoire quand d’autres modèles étaient chargés.

Un contrôle complémentaire du 22 novembre a soumis `gemma3:1b` à un cas synthétique avec un finding D2 élevé, le champ `parentProcess` manquant et une application/horaire D1 habituels. En 25,1 s, le modèle a produit une affirmation non étayée sur l’absence d’un composant système; le validateur l’a rejetée (`OLLAMA_UNSUPPORTED_SYSTEM_COMPONENT_INFERENCE`) et D3 doit reprendre son repli déterministe. Un essai précédent sur le même jeu avait aussi présenté les habitudes D1 elles-mêmes comme une alerte; des garde-fous rejettent maintenant cette contradiction. La réponse de ce modèle n’est donc pas considérée fiable pour décider seule.

Ces mesures ne sont pas des taux de précision et ne couvrent qu’un cas. Elles montrent que les modèles présents sur ce poste ne sont pas aptes à décider seuls d’une action de sécurité. Le contrôle D3 reste nécessaire : ses seuils techniques ne sont pas abaissés par une réponse faible, le mode d’action reste simulation/observation et les actions réelles sont protégées par autorisation.

En pratique, l’IA peut développer librement l’analyse des faits transmis, confronter les hypothèses bénignes et malveillantes, expliquer les lacunes, demander du contexte à D1/D2 et proposer une procédure quand une capacité manque. Le contrôle porte sur l’exécution, pas sur la réflexion : le modèle ne possède aucun outil système direct, ses brouillons restent inertes, et D3 n’exécute que des actions explicitement implémentées dans son catalogue. Les requêtes locales utilisent `127.0.0.1`; l’API Cloud exige un modèle Cloud distinct. Une session connectée à Google n’envoie donc pas par elle-même les données d’un modèle local. Si un modèle Cloud était sélectionné, ses requêtes seraient transmises au service distant; SentinelCore refuse maintenant ces tags. Voir la [politique de confidentialité Ollama](https://registry.ollama.com/privacy) et sa documentation sur les [modèles Cloud](https://ollama.com/blog/cloud-models).

Les modèles `gemma3:1b`, `gemma3:4b` et `gemma2:2b` sont déjà installés sur le poste; aucun n’a été téléchargé pendant ces tests. La durée et le code de résultat Ollama sont maintenant enregistrés dans le rapport, mais la qualité de décision doit encore être mesurée sur des scénarios annotés.

La base SQLite actuelle contient 50 scénarios, mais leurs descriptions sont des gabarits synthétiques génériques et leurs étiquettes `expected_ai` ne donnent pas toujours une décision IA détaillée. Elle permet de vérifier le branchement et le comportement de repli, pas de produire un pourcentage sérieux de qualité du modèle. Il faut enrichir les signaux et les étiquettes avant de publier un score.

L’évaluation doit comparer les sorties aux étiquettes de cas annotés et inclure au minimum : justesse des catégories de risque, demandes de contexte permises, réponses invalides, résistance aux instructions injectées dans un résumé, faux positifs/faux négatifs et latence. Une validation JSON correcte ne signifie pas que l’analyse est correcte. Les seuils d’actions sensibles ne doivent donc jamais être appris de la seule réponse du modèle.

## Lancer la démo locale

Laisser Ollama ouvert et vérifier les modèles présents avec `ollama list`. Sur ce poste, `gemma3:1b` est déjà installé. Sur un autre poste seulement, s’il manque, l’installation demandera une connexion :

```powershell
ollama pull gemma3:1b
dotnet run --project .\src\SentinelCore.Demon3.Cli\SentinelCore.Demon3.Cli.csproj -- --ollama-advisory-demo
```

Pour essayer un autre modèle installé et afficher sa durée de réponse : `dotnet run --project .\src\SentinelCore.Demon3.Cli\SentinelCore.Demon3.Cli.csproj -- --ollama-advisory-demo gemma2:2b`.

La démonstration utilise des données synthétiques. Si Ollama n’est pas disponible, elle affiche `Unavailable`. Aucun fichier, processus ou réglage Windows n’est modifié.

## Références officielles

- [API Ollama — génération d’un message de chat](https://docs.ollama.com/api/chat)
- [Ollama — sorties structurées avec un schéma JSON](https://docs.ollama.com/capabilities/structured-outputs)
- [Bibliothèque Ollama — Gemma 3 1B](https://ollama.com/library/gemma3:1b)
- [Bibliothèque GitHub Ollama](https://github.com/ollama/ollama)
- [OWASP GenAI — Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/?lang=us)
- [Microsoft Learn — Modes du langage PowerShell](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_language_modes?view=powershell-7.5)
