# SentinelCore et les protections Windows existantes

État du code et des documentations vérifié le 22 novembre 2026. Cette comparaison décrit les rôles; elle ne prétend pas mesurer la précision des produits sur un même jeu de menaces.

## Comparaison des rôles

| Solution | Ce qu’elle fournit | Place actuelle de SentinelCore |
|---|---|---|
| Microsoft Defender Antivirus | Protection anti-malware intégrée, inspection temps réel, heuristiques et surveillance comportementale. | Defender reste le moteur de protection principal. D2 lit un sous-ensemble d’événements Defender et D3 peut demander une analyse rapide autorisée. SentinelCore n’a pas de moteur de signatures, de quarantaine ni d’isolation comparable. [Protection Defender](https://learn.microsoft.com/en-us/defender-endpoint/configure-protection-features-microsoft-defender-antivirus), [surveillance comportementale](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/behavior-monitor?view=o365-worldwide) |
| Sysmon | Écrit des événements détaillés de processus, réseau, DNS, fichiers et registre dans le journal Windows. Il observe; il ne décide pas et ne bloque pas. | D2 normalise et corrèle certains de ces événements. Sa visibilité dépend de l’installation, de la configuration, de la conservation du journal et des droits du compte D2. Sur Windows 11, Sysmon est maintenant documenté comme fonctionnalité facultative intégrée; sur les autres configurations, l’installation doit être choisie et validée. [Présentation Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/overview), [événements Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events), [activation et configuration](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/how-to-enable-sysmon) |
| Microsoft Defender for Endpoint | Capacités EDR, investigations, suivi des actions et différents niveaux d’automatisation de la remédiation, selon le produit et la licence. | SentinelCore ne gère pas un parc, n’offre pas d’EDR cloud ou de centre d’action comparable et n’effectue pas la remédiation complète. Il apporte un prototype local de contexte humain et de corrélation. [Niveaux d’automatisation MDE](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/automation-levels?view=o365-worldwide), [investigation et remédiation](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-automated-investigations-remediation?view=o365-worldwide) |
| Ollama local | API locale pour appeler les modèles téléchargés sur le poste; l’API locale n’exige pas de clé. La réponse JSON structurée facilite la validation de format. | D3 peut demander une analyse de cas ambigu. Un schéma contraint la forme de la réponse, pas sa véracité. Le code valide le résultat et le limite à des avis et mesures présentes dans son catalogue typé. [API locale Ollama](https://docs.ollama.com/api/introduction), [sorties structurées](https://docs.ollama.com/capabilities/structured-outputs) |
| SentinelCore | Relie les événements D2, les habitudes/contextes D1, les décisions D3 et des rapports locaux explicables. | C’est une couche d’observation et de corrélation en développement, pas un remplacement d’antivirus ou d’EDR. Les mesures actives restent très limitées; aucune quarantaine ou interruption de processus n’est disponible. |

## Où se situe la valeur ajoutée visée

La différence recherchée n’est pas de refaire les signatures et heuristiques déjà présentes dans Defender. D1 peut fournir à D3 un contexte de session ou une comparaison visuelle quand D3 le demande; D2 apporte les faits techniques observés; D3 met ces signaux en relation et conserve sa décision avec les preuves. Ce contexte peut aider à expliquer pourquoi une action est bénigne pour une session donnée ou mérite une vérification, mais son gain de détection doit encore être mesuré.

Sysmon fournit des faits techniques, pas un verdict. Une chaîne telle que démarrage de processus → téléchargement → exécution → persistance doit être construite par un moteur d’analyse comme les règles de D2. Les événements isolés ne suffisent pas à prouver une attaque. La configuration Sysmon doit être adaptée au poste, car des filtres incomplets créent des angles morts et un volume d’événements excessif peut remplir le journal.

## Mesures disponibles et interprétation

- Les contrôles D1 couvrent les règles, l’isolation des profils, les contrats de message et 50 cas publiés de test. Le compte de contrôles n’est pas un taux de reconnaissance biométrique.
- D2 rejoue 50 scénarios synthétiques avec les sorties attendues. Le résultat 50/50 signifie que le code concorde avec ces fixtures; il ne mesure pas le taux de détection sur des logiciels malveillants réels.
- D3 possède des tests de contrat, de décision, de persistance, d’autorisation, d’IA simulée et de notifications. Le résultat 64/64 n’est pas un score de justesse d’Ollama.
- Le dernier micro-essai local D2 a traité 256 événements synthétiques à environ 468 événements par seconde. Il s’agit d’une mesure exploratoire d’un pipeline court sur un poste et non d’un benchmark comparable à Defender ou à un EDR.

Il n’existe donc pas de pourcentage de performance honnête à donner face à Defender ou Defender for Endpoint : il manque un corpus représentatif commun, des étiquettes indépendantes, un protocole reproductible, des mesures de faux positifs/faux négatifs, plusieurs postes et plusieurs profils utilisateurs. Les chiffres de tests ci-dessus ne doivent pas être présentés comme une efficacité antivirus.

## Étapes pour une comparaison valide

1. Conserver Defender actif et établir un banc de test isolé avec des échantillons et scénarios inoffensifs documentés.
2. Installer et configurer Sysmon avec une configuration versionnée; vérifier que D2 reçoit réellement chaque source et annonce toute lacune.
3. Préparer un corpus indépendant, horodaté et annoté, sans l’utiliser pour ajuster puis évaluer les mêmes règles.
4. Mesurer précision, rappel, faux positifs par heure, latence, CPU, mémoire, volume disque, pertes d’événements et comportement après redémarrage.
5. Comparer les résultats sur le même poste et le même corpus avec Defender seul, puis Defender plus SentinelCore; distinguer les gains de contexte des détections déjà fournies par Defender.

## Sources primaires consultées

- Microsoft Learn : [Microsoft Defender Antivirus](https://learn.microsoft.com/en-us/defender-endpoint/configure-protection-features-microsoft-defender-antivirus), [Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/overview), [Defender for Endpoint automation](https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/automation-levels?view=o365-worldwide).
- Ollama : [API locale](https://docs.ollama.com/api/introduction), [sorties structurées](https://docs.ollama.com/capabilities/structured-outputs).
