# SentinelCore Control Center

Application WPF locale pour lancer et surveiller les exécutables de Demon 1, Demon 2, Demon 3 et l’instance Ollama locale.

## Démarrer

Depuis la racine SentinelCore :

```powershell
dotnet build '.\Control Center\SentinelCore.ControlCenter.slnx' -c Release
dotnet run --project '.\Control Center\SentinelCore.ControlCenter\SentinelCore.ControlCenter.csproj' -c Release
```

Le Centre de contrôle commence par demander l’identité du propriétaire avec le même choix que D1 : reconnaissance faciale locale si un profil est enrôlé, ou mot de passe maître. Il réutilise le magasin protégé DPAPI de D1. Si le compte n’a pas encore de mot de passe maître, le premier lancement affiche la configuration de D1.

Pour vérifier l’échange réel entre les exécutables D2 et D3 sans toucher à leurs bases usuelles, lance depuis la racine du workspace :

```powershell
.\scripts\Verify-InterDaemonTransport.ps1
```

Pour rejouer le même contrôle avec des exécutables installés, fournis leurs chemins avec `-D2ExecutablePath` et `-D3ExecutablePath`. Le test construit toujours les projets sources de référence, démarre les fichiers indiqués et utilise des bases temporaires nettoyées après arrêt.

Le script construit D2/D3, démarre leurs processus de production, vérifie le listener puis un ACK, et utilise des bases temporaires nettoyées après arrêt. Il collecte les sources Windows disponibles pendant quelques secondes; il ne lance pas la caméra ni d’action de remédiation.

Pour vérifier aussi le démarrage de D3 avec la capacité d’analyse rapide Defender autorisée (sans lancer d’analyse), ajoute `-EnableDefenderScanMode` au script. `-ProbePowerShellCapture` tente un test réel et inoffensif du journal 4104; il inscrit une entrée bénigne dans le journal PowerShell natif de Windows. Si Windows n’émet pas de nouvel événement pour ce probe, le script le signale comme non vérifié et ne le compte pas comme réussi. Utilise cette option seulement si cette entrée de test est acceptable sur le poste.

Le bouton **Démarrer la protection** construit les solutions si leurs exécutables Release manquent, vérifie puis démarre Ollama au besoin, démarre D3 en premier puis D2, et ouvre l’écran d’apprentissage D1 intégré dans le centre. Le bouton **Démarrer D3** applique aussi cette vérification. Ollama est lancé en arrière-plan avec `ollama.exe serve` quand son API locale n’est pas joignable; un serveur déjà actif n’est pas dupliqué ni arrêté par le centre. SentinelCore ne télécharge jamais de modèle. Si le modèle configuré manque, l’interface le signale et D3 utilise ses règles de secours. D1 ne collecte rien à l’ouverture : l’utilisateur doit encore confirmer l’authentification et le démarrage depuis son écran. **Construire les modules** reconstruit D1/D2/D3 et le centre.

Le script `scripts\Build-SentinelCoreSetup.ps1` publie les quatre exécutables en autonome x64 et compile `dist\SentinelCore-Setup-1.0.0.exe` avec l’icône SentinelCore. Il installe dans le profil Windows, inclut les quatre modèles visuels locaux après vérification de leurs SHA-256 et laisse les bases de l’utilisateur intactes à la désinstallation. Il faut le SDK .NET 10, Inno Setup 6.7.4 et les quatre modèles déjà présents dans `%LocalAppData%\SentinelCore\Demon1Learning\models`. La version livrée est non signée.

La navigation **Activités D2 / D3** réunit les événements et constats locaux de D2 avec les rapports de décision D3. Elle lit les bases SQLite en lecture seule et s’actualise périodiquement. Le panneau **Rapports de sécurité** ouvre l’historique d’activité D1/D2 et de décisions D3; le bouton d’instantané y crée un rapport à la demande. D3 enregistre l’ouverture de sa session, des instantanés toutes les cinq minutes et une clôture à l’arrêt propre. Une coupure brutale peut empêcher le rapport final; la session sera signalée interrompue au prochain lancement. Le bandeau de transport sépare l’écoute D3, l’accusé de réception D2 et le handshake D1; un processus présent n’est pas considéré comme une preuve de communication.

Les chemins sont résolus depuis le dossier de sortie ou choisis dans la fenêtre; le workspace et le modèle IA choisi sont enregistrés dans `%LocalAppData%\SentinelCore\ControlCenter\settings.json`. Les rapports sont lus via le magasin D3 dans `%LocalAppData%\SentinelCore\Demon3\reports`.

## Mode d’exploitation

- Ollama est interrogé uniquement sur `127.0.0.1:11434`; aucun téléchargement de modèle n’est lancé par le centre. Le modèle `gemma3:1b` est le défaut et le menu propose les modèles présents localement avec des poids non nuls; les noms de modèle Cloud sont refusés par le centre et D3. Le choix est transmis à D3 lors de son prochain démarrage. Le gestionnaire du centre ne ferme qu’un processus Ollama qu’il a lui-même lancé, et seulement lorsque D3 s’est arrêté; il laisse un serveur préexistant intact.
- Une connexion à Ollama avec un compte Google ne modifie pas l’API locale. Les appels Cloud nécessitent un modèle Cloud séparé; SentinelCore ne les envoie pas.
- Le bouton **Tester l’inférence** vérifie une vraie réponse JSON locale, mais ne mesure pas la justesse des décisions de sécurité.
- Le centre ne crée ni ne modifie un service Windows et ne change pas la configuration Sysmon.
- D2 tourne comme processus interactif dans la session de l’utilisateur et utilise son dossier `%LocalAppData%`; la version installée comme service SCM utilise `%ProgramData%` et exige une ACL de déploiement. D2 observe les alertes Defender autorisées et Sysmon s’il est présent et configuré. « Processus actif » ne signifie pas que chaque source de télémétrie est saine.
- L’interface D1 est hébergée par le centre à partir du même contrôle WinForms que l’application autonome. Le collecteur reste un processus D1 distinct, lancé avec le chemin explicite de son exécutable. Le mode d’apprentissage exige toujours une authentification et une confirmation séparées.
- D3 n’annonce « listener prêt » qu’après la création effective du Named Pipe. Ses erreurs d’initialisation sont désormais consignées et propagées. D2 émet un état de transfert après le premier ACK et n’imprime plus les tentatives répétées comme des erreurs distinctes.
- Le mode action D3 reste en simulation par défaut. La configuration du centre peut autoriser l’analyse rapide Microsoft Defender. Après redémarrage de D3, cette mesure n’est disponible que pour un constat D2 `THREAT_FINDING` de niveau élevé, une décision D3 de risque élevé et une nouvelle saisie valide du mot de passe maître dans D1. Les autres mesures restent simulées ou bloquées; aucun script généré par l’IA n’est exécuté et le confinement/quarantaine n’est pas disponible.
- Le bouton d’arrêt envoie `STOP` aux démons console puis attend leur fermeture. Si D1 doit terminer une collecte, sa fenêtre conserve le contrôle et le centre reste ouvert.

## Limites connues

### Démarrage et fermeture

Dans **Configuration**, deux réglages facultatifs sont disponibles. **Démarrer à l’ouverture de ma session Windows** inscrit le chemin du Centre dans la clé de démarrage de l’utilisateur connecté; le Centre demande d’abord l’authentification habituelle, puis démarre automatiquement D2 et D3. D1 n’active jamais l’apprentissage sans sa propre authentification et confirmation. Décocher le réglage supprime cette entrée du démarrage Windows.

**Laisser les démons actifs quand je ferme le Centre** ferme la fenêtre sans envoyer `STOP` aux processus D1/D2/D3 démarrés. Cela les laisse vivre dans la session Windows actuelle, mais ne les surveille pas et ne les relance pas s’ils s’arrêtent. Le collecteur D1 séparé peut poursuivre une collecte déjà autorisée; le canal D1↔D3, la publication du contexte et le service de vérification visuelle restent hébergés dans le Centre et s’interrompent à sa fermeture. Pour cette raison, le réglage de fermeture en arrière-plan ne constitue pas encore une supervision complète par service Windows. À la prochaine ouverture de session, le démarrage automatique demande une nouvelle authentification.

Le centre fournit l’interface de pilotage, pas la preuve d’une protection antivirus complète. La couverture dépend des fonctionnalités réellement disponibles dans D1/D2/D3, du paramétrage de Sysmon, de l’accès au journal, des modèles OpenCV et de l’état d’Ollama. La page activités peut confirmer un listener prêt et des ACK reçus quand les démons sont lancés par le centre; pour les processus externes, leur état de transport reste inconnu tant qu’aucun signal n’a été observé.

Le mot de passe maître doit être défini dans l’interface D1. Aucun mot de passe n’est inclus dans le code, les paramètres du centre, ses journaux ou le dépôt.
