# Démon 1 — moniteur d’identité et d’interaction humaine

Le démon 1 reconnaîtra le propriétaire visuellement et comportementalement, comparera les signaux à l’activité active du poste, estimera si une autre personne ou une automatisation manipule l’ordinateur et signalera les écarts au démon 3. Le démon 2 demeure responsable de la télémétrie de menace et des processus Windows natifs; le démon 3 corrèle et décide.

## Lots de travail

- [Mode_Apprentissage](Mode_Apprentissage/README.md) : calibration et stockage protégé du profil de comportement. C’est le premier lot implémenté.
- [Spécification générale](PROPOSITION_TECHNIQUE.md) : architecture cible, sources Windows, contrat D1→D3, seuil de divergence >60 et critères d’acceptation.

Le contrôleur D1 et le collecteur clavier/souris sont intégrés. Après authentification et démarrage manuel, D1 enregistre des agrégats de rythme de frappe, de souris, d’application au premier plan, d’horaires et de ressources. La validation comportementale compare ces agrégats au profil sélectionné et envoie à D3 une divergence catégorisée; elle ne collecte pas le texte saisi ni la ligne de commande.

La vérification visuelle à la demande est dans [Mode_Validation](Mode_Validation/README.md). Après enrôlement d’un profil et activation du réglage, D1 peut capturer quelques secondes quand D3 demande une identité lors d’une alerte. Elle utilise les modèles locaux documentés, garde les images et gabarits chiffrés localement et transmet un résultat minimal à D3. Elle n’est pas une authentification Windows et ne tourne pas en continu.

Limites d’exploitation : le contrôleur D1 doit être ouvert et l’apprentissage explicitement démarré pour publier les mesures de comportement; fermer la fenêtre coupe son client D3. La classification clavier/souris ne prouve pas qu’un périphérique d’entrée est manipulé par une personne, car du matériel d’émulation peut reproduire ces signaux. Les seuils visuels et comportementaux doivent être évalués avec des sessions indépendantes avant un usage de blocage.
