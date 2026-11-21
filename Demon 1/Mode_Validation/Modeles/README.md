# Modèles locaux du module de vérification visuelle

Les poids ne sont pas ajoutés au dépôt Git. Ils sont récupérés une fois, avec versions et SHA-256 vérifiés, dans `%LOCALAPPDATA%\SentinelCore\Demon1Learning\models`.

Depuis PowerShell, à la racine `Demon 1` :

```powershell
powershell -ExecutionPolicy Bypass -File .\Mode_Validation\Modeles\Download-Models.ps1
```

Le moteur enchaîne YuNet (détection du visage), SFace (gabarit facial) et MiniFASNetV2 (contrôle d’une présentation papier/écran). Le modèle Facenox facultatif est également évalué en parallèle et uniquement pour mesurer la différence sur la webcam cible; il ne peut pas valider le liveness ni modifier un résultat d’identité. Ces briques ne sont pas interchangeables : un visage trouvé n’établit pas une identité, et une bonne similarité ne prouve pas une présence vivante.

Le score Facenox est inscrit dans les diagnostics pour permettre une comparaison A/B sur les mêmes images. Il n’influence jamais le verdict tant que son fonctionnement n’a pas été vérifié sur cette caméra et contre des essais photo/écran. Son prétraitement reprend la référence amont : coupe carrée agrandie 1,5×, RGB, entrée 128×128 et pixels normalisés entre 0 et 1.

## Fichiers et licences indiquées par les dépôts amont

| Fichier | Usage | Licence amont | SHA-256 épinglé |
|---|---|---|---|
| `face_detection_yunet_2023mar.onnx` | Détecter un visage et ses repères | MIT (OpenCV Zoo) | `8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4` |
| `face_recognition_sface_2021dec.onnx` | Comparer deux représentations faciales | Apache-2.0 (OpenCV Zoo) | `0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79` |
| `MiniFASNetV2.onnx` | Détecter certaines présentations imprimées/rejouées | Code d’inférence Apache-2.0; poids issus de Silent-Face-Anti-Spoofing | `b32929adc2d9c34b9486f8c4c7bc97c1b69bc0ea9befefc380e4faae4e463907` |
| `Facenox-MiniFASNetV2-SE.onnx` | Modèle anti-usurpation alternatif, calculé en parallèle pour comparer ses scores | Version `v1.0.0`, licence Apache-2.0 selon le dépôt amont; score uniquement diagnostique, sans effet sur `MATCH` | `af2381b88f38769222ed93379e12444e2a50814575de1c46170de570c55a42b6` |

Le seuil SFace de 0,363 est un point de départ publié pour LFW, pas un seuil de sécurité SentinelCore. Il devra être calibré sur plusieurs jours, plusieurs personnes, la webcam réelle, avec faux rejets et fausses acceptations mesurés. Le dossier amont de SFace affiche Apache-2.0 mais la provenance exacte des données d'entraînement de ce poids précis reste une question ouverte; ne pas redistribuer ce poids dans une version commerciale avant revue des droits. Le projet Silent-Face indique Apache-2.0 pour son code et ses ressources, mais la provenance des données d'entraînement du poids MiniFASNet reste à documenter séparément. MiniFASNet ne bloque pas toute usurpation : un résultat non clair devient `INDETERMINATE`, jamais `MATCH`.

Références : [OpenCV Zoo YuNet](https://github.com/opencv/opencv_zoo/tree/main/models/face_detection_yunet), [OpenCV Zoo SFace](https://github.com/opencv/opencv_zoo/tree/main/models/face_recognition_sface), [inférence MiniFASNet ONNX](https://github.com/yakhyo/face-anti-spoofing), [modèle d’origine](https://github.com/minivision-ai/Silent-Face-Anti-Spoofing), [Facenox MiniFASNetV2-SE et ses limites](https://github.com/facenox/face-antispoof-onnx).
