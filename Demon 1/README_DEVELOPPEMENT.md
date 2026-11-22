# Demon 1 — noyau comportemental

## Arborescence
- `src/SentinelCore.Demon1.Core`: moteur, admission, statistiques, stockage DPAPI et publication.
- `src/SentinelCore.Demon1.Simulations`: démo locale.
- `tests/SentinelCore.Demon1.Tests`: tests sans framework tiers et fixtures exportées SQLite.
- `PROPOSITION_TECHNIQUE.md`: audit et choix algorithmiques.

## Exécution
Depuis ce dossier: `dotnet build SentinelCore.Demon1.slnx`; `dotnet run --project tests/SentinelCore.Demon1.Tests`; `dotnet run --project src/SentinelCore.Demon1.Simulations`.

## Algorithmes
Pour chaque variable: médiane et dispersion robuste max(1.4826*MAD, IQR/1.349), score robuste, seuil provisoire 3.5. Heures modélisées en buckets de deux heures/jour de semaine, jamais en différence linéaire autour de minuit. Profil immature/échantillon faible produit faible confiance. Admission exige consentement, qualité >=0.80 et aucune suspicion Guard, finding sérieux D2, conflit, capteur dégradé ou caractéristique atypique. Le gel persiste jusqu’à reprise explicitement authentifiée.

## Profil et vie privée
DPAPI CurrentUser avec entropy liée au SID; écriture atomique initial/current/snapshots quotidiens d’historique, métadonnées minimales des échantillons refusés, et restauration d’une version avec confirmation propriétaire. Aucun contenu de frappe, mot de passe, presse-papiers, image ou trajectoire souris. L’installateur futur devra appliquer les ACL restrictives au répertoire racine. Pas de capteur réel ni de Named Pipe production dans cette première implémentation; bus JSONL simulation seulement.

## Limites
Algorithme de départ non validé sur poste réel; buckets horaires simples, aucun benchmark ni test longue durée. Les 50 cas synthétiques vérifient le mécanisme, pas un taux de performance terrain. Pas de River/Elastic/UEBA comme dépendance; comparaison dans PROPOSITION_TECHNIQUE.md.

## Dépendances
Aucun package NuGet tiers; DPAPI natif Windows; .NET 10.
