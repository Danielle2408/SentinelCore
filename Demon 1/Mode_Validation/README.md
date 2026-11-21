# Démon 1 — validation et identité visuelle locale

Cette partie compare le comportement récent au profil sélectionné, puis, sur demande liée à une alerte, peut comparer le visage à un des profils visuels enregistrés. Elle ne prend pas la décision de risque finale et ne lance pas d’action.

## Fonctionnement

- `SentinelCore.Demon1.Validation` compare les mesures comportementales aux mesures apprises et signale une divergence à D3 si la qualité des données le permet.
- `SentinelCore.Demon1.VisualVerification` capture environ 5 secondes quand D3 demande une vérification, cherche un seul visage, produit un gabarit SFace, vérifie la présence réelle avec MiniFASNetV2, puis compare aux profils visuels. OpenCvSharp 5 exécute aussi le réseau anti-usurpation localement sur CPU.
- D1 renvoie uniquement un statut à trois valeurs, les mesures de qualité, le profil candidat éventuel, un code de motif et une référence d’image. Il n’envoie jamais les images, les frappes ou les gabarits à D2.
- Les gabarits et les preuves locales sont chiffrés avec DPAPI. D3 peut demander des morceaux de la preuve en utilisant `VISUAL_EVIDENCE_READ_REQUEST`; il l’intègre au rapport avant purge locale.
- Après activation et enrôlement dans les paramètres, les demandes d’alerte ne déclenchent pas une boîte de dialogue répétée. La caméra ne tourne pas continuellement.

## Installation des modèles et démarrage

Dans PowerShell, depuis le dossier `Demon 1` :

```powershell
powershell -ExecutionPolicy Bypass -File .\Mode_Validation\Modeles\Download-Models.ps1
dotnet build .\SentinelCore.Demon1.slnx --configuration Release
```

Le premier script télécharge YuNet, SFace, MiniFASNetV2 et le modèle expérimental Facenox vers `%LOCALAPPDATA%\SentinelCore\Demon1Learning\models`, puis vérifie leur SHA-256. Les poids ONNX ne sont pas suivis dans Git. Facenox est évalué pour comparaison seulement; son score ne valide pas une identité. Les références, licences et limites figurent dans `Modeles/README.md` et `COMPARAISON_SOLUTIONS.md`.

Ouvrir ensuite la fenêtre de contrôle du mode apprentissage. Choisir un profil, confirmer le mot de passe maître et utiliser « Enrôler le visage » en regardant la caméra dans une pièce éclairée. Dans Paramètres, activer « Autoriser le contrôle visuel demandé par le démon 3 ». Le bouton « Tester demande D3 + caméra » crée une vraie demande D3, ouvre la caméra, capture une séquence et exécute les modèles de détection, de comparaison et d’anti-usurpation. Aucun résultat n’est préfabriqué.

Les détails des captures (nombre d’images lues, visages trouvés, taille du visage et scores de présence) sont visibles avec les résultats dans « Rapports visuels ». Une caméra indisponible, aucun visage, plusieurs visages, une faible qualité ou une présence non confirmée doit donner un résultat `INDETERMINATE`, jamais une identité positive.

Le réglage actuel de la webcam de test accepte un visage d’au moins 80 pixels. MiniFASNetV2 utilise un seuil `LIVE` de 0,60; entre 0,40 et 0,60 le résultat reste `INDETERMINATE`, et à 0,40 ou moins la capture est marquée `SPOOF_SUSPECTED`. La décision compare la probabilité moyenne des images retenues. Ces seuils sont des réglages de cette version, pas des garanties mesurées contre toute photo, vidéo ou autre personne. L’essai du 21 novembre 2026 a obtenu un `MATCH` propriétaire (similarité SFace 0,943) après la correction d’un défaut de lecture des sorties ONNX; consulter `ESSAIS_REELS_D1.md` avant d’interpréter les captures antérieures.

Le programme `simulation/SentinelCore.Demon1.VisualSimulation` peut aussi vérifier les cas techniques depuis PowerShell : `--camera-d3` essaie l’enrôlement puis l’appel D3 réel, `--camera-request` fait l’appel D3 avec la webcam réelle, `--camera-failure` vérifie une caméra indisponible, et `--camera-deadline` déclenche une échéance D3 courte sur la vraie caméra. Pour éviter le chargement de la DLL native OpenCV depuis un chemin profond, publier le simulateur Win-x64 dans un chemin court (`C:\scv`) puis lancer son exécutable depuis là. Les essais écrivent des résultats sans conserver les captures ni les profils temporaires.

```powershell
dotnet publish .\Mode_Validation\simulation\SentinelCore.Demon1.VisualSimulation\SentinelCore.Demon1.VisualSimulation.csproj -c Release -r win-x64 --self-contained false -p:UseAppHost=true -o C:\scv
& C:\scv\SentinelCore.Demon1.VisualSimulation.exe --camera-d3
```

## Interface inter-démons

Le transport demeure la propriété de D3, qui héberge `\\.\pipe\SentinelCore.Guard`; le nouveau `InterDaemonPipeClient` de D1 s’y connecte en local. Il utilise une longueur little-endian suivie d’un message JSON, limite les messages à 64 KiB, réalise HELLO/WELCOME, envoie un heartbeat toutes les 10 secondes, exige les ACK, retente trois fois au plus et rejette types/version/expirations inattendus. D1 envoie `USER_CONTEXT` pendant la collecte et `BEHAVIOR_DEVIATION` uniquement si l’évaluation faite **avant la mise à jour du profil** dépasse le seuil. Il répond aussi à `CONTEXT_REQUEST`, `VISUAL_IDENTITY_REQUEST` et `VISUAL_EVIDENCE_READ_REQUEST`. D3 doit activer ces types dans sa liste autorisée; seul D3 décide du risque et des actions. L’attente visuelle peut durer jusqu’à 60 secondes, sans suspendre l’évaluation urgente de D2. Voir `CONTRAT_VISUEL_D1_D3.txt`.

Quand la fenêtre D1 est ouverte, elle tente de se connecter au Named Pipe de D3, effectue le HELLO/WELCOME, envoie un heartbeat et répond aux demandes visuelles/contexte. Le contexte et les divergences ne sont publiés que pendant une collecte d’apprentissage explicitement démarrée. Cette branche ne transforme pas encore le contrôleur en service Windows démarré à chaque ouverture de session; fermer la fenêtre coupe donc ce client D1. D3 doit implémenter les types ajoutés dans le contrat partagé et intégrer les preuves au rapport.

Le banc de tests crée un serveur Named Pipe D3 factice pour vérifier le vrai client D1 : handshake, ACK, contexte, demande de vérification et réponse corrélée. Il ne valide pas le futur serveur D3, ses ACL ni l’intégration complète des deux exécutables.

## Prudence de mesure

Le seuil SFace 0,363 vient d’un benchmark public LFW; ce n’est ni un taux de fiabilité SentinelCore ni une probabilité. Le score est seulement un indice de similarité. Le seuil et le contrôle de présence doivent être évalués sur des sessions séparées par jour et par utilisateur. Une capture absente ou ambiguë doit rester `INDETERMINATE`.
