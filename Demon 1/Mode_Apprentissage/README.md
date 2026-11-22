# Démon 1 — mode apprentissage

## Lancer l’application

L’application de contrôle Windows se trouve après publication dans `artifacts/win-x64/SentinelCore.Demon1.Learning.Controller.exe`. Double-clique sur ce fichier pour ouvrir la fenêtre de suivi. Elle ne démarre jamais la collecte automatiquement.

Pour reconstruire le fichier exécutable depuis la racine du dépôt :

```powershell
.\Demon 1\Mode_Apprentissage\build-release.ps1
```

Le script PowerShell `Controler-Apprentissage.ps1` est maintenant un simple lanceur de l’EXE; toute la configuration et le suivi se font dans la fenêtre.

## Autoriser une étude

À la première ouverture, la fenêtre demande de créer le mot de passe maître (12 caractères minimum). Seule une empreinte PBKDF2 salée est stockée; le fichier est en plus chiffré avec DPAPI pour le compte Windows courant.

Aux ouvertures suivantes, le propriétaire choisit entre son mot de passe maître et la reconnaissance faciale locale de SentinelCore. Le bouton visage n’est disponible qu’après l’enrôlement d’au moins un profil. Le moteur utilise la webcam et les modèles locaux YuNet, SFace et MiniFASNetV2; il ne s’appuie pas sur Windows Hello. Si la vérification faciale échoue ou reste indéterminée, l’application ne s’ouvre pas par cette voie et le mot de passe maître reste proposé.

Après authentification, une collecte d’apprentissage doit encore être démarrée explicitement et confirmée. Le collecteur exige aussi un ticket protégé DPAPI à usage unique, valable 30 secondes, remis par le contrôleur après authentification.

## Paramètres et suivi

La fenêtre permet :

- d’ouvrir l’application par reconnaissance faciale locale ou mot de passe maître;
- de démarrer l’apprentissage après authentification et confirmation explicite;
- d’arrêter la collecte manuellement;
- de suivre l’état et les dernières mesures en temps réel;
- de consulter les 200 dernières périodes enregistrées;
- de modifier la période de mesure (10–60 s) et l’arrêt après inactivité (30–900 s);
- de configurer jusqu’à huit profils et de choisir le profil auquel rattacher une session d’apprentissage;
- de voir un résumé des programmes souvent au premier plan, des heures observées et de leur utilisation médiane du CPU/de la mémoire;
- de régler la conservation de l’historique des applications et ressources (1 à 90 jours, 30 jours par défaut);
- de changer le mot de passe maître après vérification de l’ancien.

La base est enregistrée dans `%LOCALAPPDATA%\SentinelCore\Demon1Learning\learning.db`. Les profils et mesures sont chiffrés par DPAPI par compte utilisateur Windows. Le mot de passe maître et les empreintes sont enregistrés dans `auth.bin`, également protégé DPAPI. Les préférences générales sont dans `settings.json`.

Dans la fenêtre « Voir la base », les dates, contextes, états, décisions et noms des mesures sont présentés en français. Les noms techniques de tables/colonnes et les identifiants internes restent stables pour préserver la compatibilité avec le code et les anciennes bases.

## Données collectées

Le collecteur Windows Raw Input agrège les événements par période : fréquence de frappe, durée d’appui, intervalle et pauses entre frappes, vitesse/accélération/curvature de la souris et intervalles de clic. Les codes de touches n’existent qu’en mémoire le temps de calculer une durée d’appui; aucun caractère ni texte n’est écrit dans le profil. Les événements de frappe/souris sont réinitialisés à chaque période et leur historique SQLite est supprimé après 24 heures; seuls les résumés bornés du profil restent pour l’apprentissage.

Pendant une collecte, le collecteur appelle les API Windows une fois par seconde pour connaître le nom simple du processus au premier plan, l’heure et le jour, la durée observée, son utilisation CPU/mémoire et la mémoire utilisée par le système. Il agrège ces données par période et profil, les protège par DPAPI, puis les conserve selon le réglage de 1 à 90 jours (30 jours par défaut), avec un plafond de 20 000 périodes par profil. Les noms de fenêtre, commandes lancées, chemins de fichiers et contenus ne sont pas collectés par D1. Les profils d’apprentissage 1 à 8 restent séparés.

Le système écarte les événements bruts lorsque le collecteur est au premier plan, n’enregistre pas de mesure clavier/souris si l’activité est insuffisante et interrompt la collecte après le délai d’inactivité configuré. Les horaires, applications de premier plan et ressources sont collectés par profil. La validation comportementale compare clavier/souris; l’identité visuelle locale (YuNet/SFace/MiniFASNetV2), les rapports et les échanges avec D3 sont présents. Le contrôleur doit rester ouvert pour maintenir son client local connecté au pipe de D3. Cette collecte est réelle mais démarrée manuellement : ce n’est pas encore un service Windows démarré avant l’ouverture de session. Raw Input décrit le périphérique d’entrée; un périphérique matériel émulant une personne peut donc imiter un clavier ou une souris.

## Structure

- `src/SentinelCore.Demon1.Learning` : profils, règles d’admission, SQLite, DPAPI et ticket de démarrage à usage unique.
- `src/SentinelCore.Demon1.Learning.Collector` : collecte Windows clavier/souris et écriture de l’état.
- `src/SentinelCore.Demon1.Learning.Controller` : interface WinForms, mot de passe maître, choix d’authentification faciale, paramètres et rapports.
- `simulation` : simulation de calibration et test de fumée du collecteur publié.
- `fonctionnement.txt` : explication simple, exemples et comportement attendu.

La branche de travail est `feature/demon-1-validation`. Le contrôleur, l’apprentissage et la validation restent dans le dossier de ce module.

## Vérification effectuée

- `dotnet build Demon 1/SentinelCore.Demon1.slnx --configuration Release` : réussi sur l’état courant, 0 avertissement et 0 erreur (21 novembre 2026).
- Publication autonome `win-x64` en fichier unique : réussie.
- Simulation d’apprentissage synthétique : 70/70 périodes admissibles acceptées et 2/2 périodes inadmissibles rejetées; 322 périodes SQLite persistées et relues. Ces pourcentages évaluent uniquement les règles sur des données synthétiques, pas la reconnaissance du propriétaire.
- Test fumée du collecteur publié : un `status.json` déjà présent a été mis à jour, le ticket a été consommé une fois, l’arrêt a été appliqué, puis le JSON final a été relu. Une preuve incorrecte a été refusée et un test temporaire a vérifié que le mot de passe maître fonctionne sans apparaître en clair dans le fichier. L’exception d’accès montrée auparavant n’est pas réapparue.
- Authentification faciale : le code de la fenêtre propose visage local ou mot de passe maître après la première configuration. Le scénario de caméra a été exécuté en CLI pour ne pas créer ou saisir un mot de passe maître pendant le test.
- Tests webcam réels : les résultats et limites d’enrôlement, l’absence de visage, le refus de liveness et l’indisponibilité caméra sont consignés dans `Mode_Validation/ESSAIS_REELS_D1.md`.
- Tests comportementaux : `dotnet run --project tests/SentinelCore.Demon1.Tests --configuration Release --no-build` exécute les contrôles du moteur et rejoue les 50 cas publiés; tous passent. Cela ne mesure pas la reconnaissance biométrique.

Le taux de faux rejet/faux acceptation du futur module de validation n’est pas mesurable avec ce module d’apprentissage seul. La collecte terrain (durées, variations d’appareils et qualité des mesures) reste à évaluer sur des sessions choisies par le propriétaire.

## Documentation Windows

- [Windows Raw Input](https://learn.microsoft.com/en-us/windows/win32/inputdev/using-raw-input)
- [OpenCV Zoo — YuNet et SFace](https://github.com/opencv/opencv_zoo)
- [MiniVision — Silent-Face-Anti-Spoofing](https://github.com/minivision-ai/Silent-Face-Anti-Spoofing)
- [Exemple ONNX MiniFASNetV2 et webcam](https://github.com/yakhyo/face-anti-spoofing)
