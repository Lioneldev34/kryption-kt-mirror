#!/bin/sh
#
# Surveillance EXTERNE du journal de transparence de l'annuaire (KT-3).
#
# ⚠️ Ce script n'a de valeur QUE s'il tourne ailleurs que sur le serveur Kryption.
# Un audit exécuté sur la machine surveillée ne détecte pas une machine compromise :
# un attaquant qui la contrôle logge sa fausse racine, obtient une vraie proof
# Sigsum, et écrit un mensonge cohérent partout. La détection vient du dehors.
#
# Ce que le script vérifie, sans faire confiance au serveur :
#   1. `sth_hash` est bien le haché des octets canoniques de la tête publiée. C'est
#      le maillon que le serveur NE PEUT PAS vérifier lui-même : le faire côté
#      serveur exigerait une seconde implémentation de l'encodage canonique, la
#      chose même que tout le chantier s'interdit. Ici c'est au contraire un atout —
#      une implémentation indépendante est ce qui donne du sens à la vérification.
#   2. chaque `sth_hash` du miroir est réellement loggé dans Sigsum (proof valide
#      contre la policy ÉPINGLÉE, hors ligne) ;
#   3. les têtes s'enchaînent (prev_sth_hash[n] == sth_hash[n-1]) ;
#   4. ce que l'API publie sur /kt/sth correspond, epoch par epoch, au miroir.
#
# Ensemble, 1 et 2 lient la racine publiée à la racine ancrée : sans 1, un serveur
# pourrait publier une racine et en ancrer une autre.
#
# Une divergence entre l'API et le miroir signifie que l'un des deux ment, et un
# observateur extérieur ne peut pas savoir lequel : c'est le signal d'alarme.
#
# Prérequis : git, curl, jq, python3, et le binaire sigsum-verify (Go) :
#   go install sigsum.org/sigsum-go/cmd/sigsum-verify@v0.14.1
#
# Usage, depuis un clone du miroir — rien à configurer :
#   ./kt-external-watch.sh
#
# ⚠️ AVANT la première exécution, épinglez la clé publique de soumission.
# Elle est livrée dans ce dépôt par commodité, mais le dépôt est poussé par le
# serveur : un serveur compromis pourrait y déposer SA clé, et ses fausses feuilles
# se vérifieraient parfaitement. Le dépôt s'attesterait lui-même.
# Comparez son empreinte à celle publiée hors bande (site, notes de version) :
#
#     ssh-keygen -lf submit.key.pub
#     → 256 SHA256:TzPO6MaHaqDRSHZ9rKSxqkjlPo58kdzu6MgZIqFjrhg sigsum key (ED25519)
#
# Même logique pour POLICY : c'est elle qui décide qu'une preuve est valable, pas
# la preuve. Ne l'acceptez pas depuis une source que le serveur contrôle.

set -eu

# Ces trois valeurs sont publiques et fixes. Elles sont ici pour qu'un vérificateur
# n'ait rien à deviner : cloner puis lancer doit suffire.
MIRROR_URL="${MIRROR_URL:-https://github.com/Lioneldev34/kryption-kt-mirror.git}"
API_URL="${API_URL:-https://api.kryption.fr/api/kt/sth}"
SUBMIT_PUBKEY="${SUBMIT_PUBKEY:-$(dirname "$0")/submit.key.pub}"

# ⚠️ `sigsum-test-2025-3` tant que l'ancrage tourne sur les logs de TEST. Passera à
# `sigsum-generic-2025-1` (production) — et ce changement est visible dans ce
# fichier, donc dans l'historique public.
POLICY="${POLICY:-sigsum-test-2025-3}"

SIGSUM_VERIFY="${SIGSUM_VERIFY:-sigsum-verify}"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
FAILURES=0

fail() {
    echo "⛔️ $1" >&2
    FAILURES=$((FAILURES + 1))
}

# Recalcule le haché de tête depuis les champs publiés, selon l'encodage figé de
# `crates/core/src/kt/sth.rs` :
#     SHA-256("kryption-kt-sth:v1\0" ‖ epoch(u64 LE) ‖ root ‖ prev ‖ ts(u64 LE))
# Implémentation volontairement indépendante de celle du serveur.
head_hash() {
    python3 - "$1" "$2" "$3" "$4" <<'PY'
import base64, hashlib, struct, sys
epoch, root_b64, prev_b64, ts = int(sys.argv[1]), sys.argv[2], sys.argv[3], int(sys.argv[4])
body = (b"kryption-kt-sth:v1\x00"
        + struct.pack("<Q", epoch)
        + base64.b64decode(root_b64)
        + base64.b64decode(prev_b64)
        + struct.pack("<Q", ts))
print(base64.b64encode(hashlib.sha256(body).digest()).decode())
PY
}

# ── 1. Le miroir, tel que le monde le voit ──────────────────────────────────
git clone --quiet --depth 50 "$MIRROR_URL" "$WORK/mirror"
cat "$WORK/mirror"/roots/*.jsonl 2>/dev/null | jq -c 'select(.epoch != null)' | sort -t: -k2 -n > "$WORK/lines"

if [ ! -s "$WORK/lines" ]; then
    fail "le miroir ne contient aucun epoch"
    exit 1
fi

echo "── $(wc -l < "$WORK/lines") epoch(s) dans le miroir ──"

PREV_HASH=""
PREV_EPOCH=""

while IFS= read -r line; do
    EPOCH=$(printf '%s' "$line" | jq -r '.epoch')
    STH_HASH=$(printf '%s' "$line" | jq -r '.sth_hash_b64')
    PREV=$(printf '%s' "$line" | jq -r '.prev_sth_hash_b64')
    ROOT=$(printf '%s' "$line" | jq -r '.root_b64')
    TS=$(printf '%s' "$line" | jq -r '.timestamp')

    # 1a. Le haché ancré est-il celui de la tête publiée ? Sans ce contrôle, un
    #     serveur pourrait publier une racine et en ancrer une autre.
    RECOMPUTED=$(head_hash "$EPOCH" "$ROOT" "$PREV" "$TS")
    if [ "$RECOMPUTED" != "$STH_HASH" ]; then
        fail "epoch $EPOCH : le haché ancré n'est PAS celui de la tête publiée"
    fi

    # 1b. La racine est-elle réellement loggée ? Vérification HORS LIGNE contre la
    #     policy épinglée : ce n'est pas la proof qui décide de sa validité.
    printf '%s' "$line" | jq -r '.sigsum_proof' > "$WORK/proof"
    printf '%s' "$STH_HASH" | base64 -d > "$WORK/msg" 2>/dev/null || fail "epoch $EPOCH : sth_hash illisible"

    if ! "$SIGSUM_VERIFY" -k "$SUBMIT_PUBKEY" -P "$POLICY" --raw-hash "$WORK/proof" < "$WORK/msg" >/dev/null 2>&1; then
        fail "epoch $EPOCH : la proof Sigsum ne couvre pas cette tête, ou ne satisfait pas la policy"
    fi

    # 1c. La chaîne se tient-elle ?
    if [ -n "$PREV_EPOCH" ]; then
        if [ "$EPOCH" -ne $((PREV_EPOCH + 1)) ]; then
            fail "trou dans la chaîne : epoch $EPOCH suit $PREV_EPOCH"
        fi
        if [ "$PREV" != "$PREV_HASH" ]; then
            fail "epoch $EPOCH ne s'enchaîne pas sur la tête de l'epoch $PREV_EPOCH"
        fi
    fi

    PREV_HASH="$STH_HASH"
    PREV_EPOCH="$EPOCH"
done < "$WORK/lines"

# ── 2. Ce que le serveur publie, maintenant ─────────────────────────────────
curl -fsS "$API_URL?limit=100" > "$WORK/api.json" || fail "l'API ne répond pas"

if [ -s "$WORK/api.json" ]; then
    jq -r '.sth[] | "\(.epoch) \(.root_b64)"' "$WORK/api.json" | while read -r EPOCH ROOT; do
        MIRRORED=$(jq -r --argjson e "$EPOCH" 'select(.epoch == $e) | .root_b64' "$WORK/lines" | head -1)

        if [ -z "$MIRRORED" ]; then
            # Normal pour les epochs récents : l'ancrage précède le miroir.
            continue
        fi
        if [ "$MIRRORED" != "$ROOT" ]; then
            echo "⛔️ epoch $EPOCH : l'API et le miroir publient des racines DIFFÉRENTES" >&2
            echo "   api    : $ROOT" >&2
            echo "   miroir : $MIRRORED" >&2
            exit 1
        fi
    done || FAILURES=$((FAILURES + 1))
fi

if [ "$FAILURES" -ne 0 ]; then
    echo "⛔️ $FAILURES anomalie(s) — le journal ne se tient pas." >&2
    exit 1
fi

echo "✅ le journal est cohérent : chaque racine est loggée, la chaîne se tient, l'API et le miroir s'accordent."
