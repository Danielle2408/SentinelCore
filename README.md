# SentinelCore

SentinelCore est un dépôt de développement de composants de sécurité pour Windows. Il regroupe actuellement deux démonstrateurs séparés : **Démon 1 — Apprentissage comportemental** et **Démon 2 — Threat Monitor**. Le dépôt n'est pas encore un produit unifié prêt à installer : le service Guard (Démon 3), l'installation complète et la validation de bout en bout sur un poste de production n'y sont pas fournis.

## Composants présents

| Composant | Fonction actuelle | Données et limites |
| --- | --- | --- |
| **Démon 1 — Apprentissage comportemental** | Établit, avec confirmation explicite du propriétaire, un profil local de mesures agrégées de saisie et d'activité souris. Il compare les fenêtres aux références statistiques du profil, signale les écarts et met en quarantaine les observations de qualité faible ou suspectes au lieu de les intégrer. | Le collecteur utilise Windows Raw Input. Il calcule des compteurs et des mesures de rythme (durée et intervalle des touches, mouvements, vitesse et clics) ; il ne conserve pas le texte saisi ni les coordonnées brutes de souris. Les profils d'apprentissage sont stockés localement sous protection DPAPI. Cette fonction constitue bien un profil comportemental et doit rester soumise au consentement et au contrôle de l'utilisateur. |
| **Démon 2 — Threat Monitor** | Lit les événements du journal opérationnel Sysmon, les normalise, les corrèle dans une fenêtre temporelle, applique un catalogue de règles déterministes et conserve localement événements, preuves, findings et messages à publier. | Il dépend de Sysmon et de sa configuration sur l'hôte. La réputation de domaine n'est pas fournie ; les éléments absents restent absents. L'implémentation est en mode observation : elle ne répond pas aux menaces et ne change pas la configuration de sécurité. Voir le [guide du Démon 2](<Demon 2/README.md>) pour le déploiement et les contrôles détaillés. |
| **Démon 3 — Guard** | Aucun code d'implémentation du Guard n'est présent dans ce dépôt. | Le test D1 publie une enveloppe v1 dans un fichier JSONL ; D2 contient le client Named Pipe de production. Le serveur Guard et l'orchestration complète ne peuvent pas être validés ici. |

Les composants D1 et D2 sont des projets distincts. Ce dépôt ne met pas en place à lui seul un flux opérationnel intégré entre les deux, et les tests de simulation ne remplacent pas une validation sur un poste Windows configuré avec les sources requises.

## Ce que fait Threat Monitor

D2 consomme le canal `Microsoft-Windows-Sysmon/Operational` au moyen d'un service Windows ou, pour le diagnostic, en mode console. Il prend en charge les observations que Sysmon peut réellement fournir : démarrage de processus, lancement d'interpréteurs, certains événements de fichiers, marque de téléchargement `Zone.Identifier`, connexions réseau, requêtes DNS, chargements de modules, accès à des processus et changements de certaines clés de registre associées à la persistance.

Le pipeline suit les étapes **collecte → normalisation → corrélation → règles → preuves → publication**. Les findings référencent les événements conservés dans SQLite. Les messages sont placés dans une outbox persistante puis envoyés au Guard via le Named Pipe local `SentinelCore.Guard`. Le client de D2 gère la session, l'échange HELLO/WELCOME et les ACK ; le serveur Guard n'est pas inclus dans ce dépôt.

D2 ne fait pas de balayage réseau, ne contacte pas les domaines observés, n'exécute pas de commandes, ne supprime ni ne chiffre de fichiers, ne modifie aucun mécanisme de persistance, ne suspend pas de processus et ne désactive pas Microsoft Defender. Il ne dépend pas d'Ollama. Sysmon doit déjà être installé et configuré ; D2 ne l'installe pas et ne le reconfigure pas.

## Environnement

- SDK .NET 10 pour compiler les projets ; les cibles sont `net10.0` et, pour le collecteur D1 utilisant Windows Forms/Raw Input, `net10.0-windows`.
- Windows est requis pour le collecteur Sysmon et le service D2, ainsi que pour les fonctions D1 qui s'appuient sur Raw Input et DPAPI.
- Les dépendances .NET sont déclarées dans les fichiers projet et restaurées par NuGet.
- Le dépôt ne fournit pas un installateur. L'inscription du service D2 auprès du Service Control Manager est une étape de déploiement manuelle décrite dans le guide D2.

## Compiler et exécuter les contrôles

Depuis la racine du dépôt, dans PowerShell :

```powershell
dotnet build 'Demon 1\SentinelCore.Demon1.slnx' -c Release
dotnet run --project 'Demon 1\tests\SentinelCore.Demon1.Tests\SentinelCore.Demon1.Tests.csproj' -c Release

dotnet build 'Demon 2\SentinelCore.Demon2.slnx' -c Release
dotnet run --project 'Demon 2\tests\SentinelCore.Demon2.Tests\SentinelCore.Demon2.Tests.csproj' -c Release
```

Les exécutables de test contiennent les contrôles unitaires et d'intégration ainsi que le rejeu des fixtures de chaque démon. Pour D2, le rejeu fourni contient 50 scénarios synthétiques. À la dernière validation consignée dans le guide D2, 38 scénarios correspondaient aux attentes structurées et 12 ont été laissés à clarifier en raison de contradictions ou d'éléments de télémétrie manquants. La couverture observée dans ces fixtures était de 10 types d'événements sur 11 et de 8 règles sur 10. Ces chiffres décrivent les fixtures, pas le taux de détection en conditions réelles.

## Limites connues

- `DOMAIN_REPUTATION` n'est pas émis : aucun fournisseur de réputation n'est configuré et aucun domaine n'est contacté.
- Les activités de script sont inférées à partir des processus interpréteurs observés ; le contenu de script n'est pas inspecté.
- La détection de téléchargement repose notamment sur la présence d'un flux alternatif `Zone.Identifier`, qui peut manquer.
- Les événements Sysmon activés dépendent de la politique de configuration locale ; une catégorie désactivée ne peut pas être reconstituée par D2.
- Les fixtures sont synthétiques. Certaines références se contredisent ou n'incluent pas la preuve requise ; elles sont signalées dans le guide et le rapport de rejeu plutôt que réécrites.
- Les tests de D2 valident le protocole Named Pipe avec un pair local de test, mais ne valident pas le serveur Guard absent. Les tests du collecteur ne remplacent pas une validation sur un poste Windows avec Sysmon et des permissions SCM/journal adaptées.
- D1 collecte des mesures de rythme de saisie et d'interaction souris sous consentement explicite. Cette capacité est séparée de D2 et ne doit pas être confondue avec la surveillance des menaces logicielles.

## Organisation du dépôt

```text
Demon 1/   Apprentissage comportemental, simulations et tests
Demon 2/   Threat Monitor, service Windows, cœur, fixtures et guide
```

Le contrat commun et les références historiques sont conservés dans leurs emplacements existants. Les fixtures sont des données de validation et ne doivent pas être modifiées pour faire passer les contrôles.
