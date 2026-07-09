# Journal de transparence de l'annuaire Kryption

Kryption permet de retrouver quelqu'un par un handle lisible — `@lionel-1234` —
qui résout vers son identité cryptographique. Le serveur qui répond à cette
question pourrait mentir : donner à Alice la clé d'un attaquant à la place de
celle de Bob. Rien, dans une réponse d'API, ne permet à Alice de le savoir.

Ce dépôt existe pour que ce mensonge soit **impossible à cacher**.

## Ce qu'il contient

Chaque heure, le serveur publie une **racine** : une empreinte de l'annuaire
entier à cet instant. Elle est signée, chaînée à la précédente, et soumise à un
**log Sigsum** public, dont la tête est co-signée par des témoins indépendants.

Une ligne JSON par epoch, dans `roots/AAAA-MM.jsonl` :

```
{"epoch":3,"root_b64":"…","prev_sth_hash_b64":"…","sth_hash_b64":"…",
 "timestamp":1783636660,"sth_signature_b64":"…","sigsum_proof":"…"}
```

Le `sigsum_proof` est autonome : il se vérifie **hors ligne**, sans rien demander
à Kryption.

## Pourquoi ce dépôt a besoin de vous

Un serveur pleinement compromis peut tenir **deux journaux valides en parallèle**.
Un pour tout le monde, un pour sa victime. Les deux s'enchaînent, les deux
vérifient. La victime ne voit que le sien et n'a aucun moyen de savoir.

Le mensonge n'existe que dans l'**écart entre ce que voient des observateurs
différents**. Il n'apparaît donc que si plusieurs personnes regardent.

Ce dépôt ne prouve rien tant que personne ne l'a cloné. C'est **votre copie** qui
rend une réécriture d'historique visible : une réécriture diverge de ce que vous
détenez déjà. Un miroir que personne n'a cloné est un miroir qui ne prouve rien.

## Vérifier vous-même

```sh
go install sigsum.org/sigsum-go/cmd/sigsum-verify@v0.14.1   # une fois
git clone https://github.com/Lioneldev34/kryption-kt-mirror.git
cd kryption-kt-mirror
./kt-external-watch.sh
```

Il n'y a rien à configurer. Le script sort `0` et une ligne verte si tout se tient,
`1` et le détail sinon.

**Avant la première exécution**, épinglez la clé publique de soumission. Elle est
livrée ici par commodité, mais ce dépôt est poussé par le serveur : un serveur
compromis pourrait y déposer *sa* clé, et ses fausses feuilles se vérifieraient
parfaitement. Le dépôt s'attesterait lui-même.

```sh
ssh-keygen -lf submit.key.pub
# 256 SHA256:TzPO6MaHaqDRSHZ9rKSxqkjlPo58kdzu6MgZIqFjrhg sigsum key (ED25519)
```

Comparez cette empreinte à celle publiée **hors de ce dépôt**. Même prudence pour
la policy Sigsum : c'est elle qui décide qu'une preuve est valable, pas la preuve.

## Ce que le script vérifie

1. **Le haché ancré est celui de la tête publiée.** Il le recalcule lui-même. Sans
   ce contrôle, le serveur pourrait publier une racine et en **ancrer une autre** :
   la preuve Sigsum serait valide, mais elle attesterait autre chose.
2. **Chaque racine est réellement dans un log Sigsum**, avec assez de co-signatures
   pour satisfaire la policy épinglée. Un attaquant qui ferait tourner son propre
   log n'y gagnerait rien.
3. **La chaîne se tient** : epochs contigus, chaque tête pointant sur la précédente.
   Un trou est indistinguable d'un fork.
4. **L'API et ce dépôt racontent la même histoire.** S'ils divergent, l'un des deux
   ment — et vous ne pouvez pas savoir lequel. C'est le signal d'alarme.

## Ce que ça ne couvre pas

Si le serveur vous sert la vérité et le mensonge à sa seule victime, ce script ne
voit rien. Il faudrait constater que **deux racines différentes** ont été loggées
pour le même epoch sous la clé de soumission ci-dessus : cela se lit dans le log
Sigsum, avec `sigsum-monitor`.

C'est aussi ce que couvre le *gossip* entre clients de l'application, qui
s'échangent les racines qu'ils ont vues.

## Si quelque chose ne va pas

Le script sort `1` et affiche l'anomalie. Dans ce cas : **conservez votre clone**,
il est la preuve. Puis dites-le publiquement.
