#!/bin/sh
# carbon-fetch.sh VERSION puts IBM Carbon's web components into the
# dashboard (Y3 of docs/development-plan-dashboard-carbon.md):
#
#   tools/carbon-fetch.sh 2.68.0
#
# It downloads IBM's ready files of @carbon/web-components VERSION from
# IBM's CDN: the components the dashboard uses, with every file they load.
# From the npm registry it takes Carbon's LICENSE, the themes of
# @carbon/styles and the icons of @carbon/icons, which tools/carbonprep
# makes into themes.css and icons.svg. Everything goes into
# internal/dashboard/web/static/carbon/, which it replaces, and is built
# into the dashboard's binary; the browser loads nothing from elsewhere.
#
# It needs curl, tar and Go, not Node.js. The versions of the styles and
# icons are set below (CARBON_STYLES, CARBON_ICONS in the environment
# change them). After a new version, look at every page in the browser,
# light and dark, before committing.
#
# A component or an icon the dashboard starts to use is added to the
# lists below, and the script run again with the same version.
set -eu

VERSION=${1:?usage: tools/carbon-fetch.sh VERSION, for example 2.68.0}
STYLES=${CARBON_STYLES:-1.120.0}
ICONS=${CARBON_ICONS:-11.92.0}

# The components, by the names of IBM's files.
COMPONENTS="ui-shell button icon-button tag notification content-switcher
toggle-tip text-input password-input textarea number-input select checkbox
toggle modal progress-bar inline-loading skeleton-text code-snippet
copy-button breadcrumb file-uploader tooltip pagination"

# The icons, by their names in @carbon/icons.
ICON_NAMES="dashboard warning--alt user--multiple api application rule
test-tool document--import settings activity data--base pending user--admin
recently-viewed settings--adjust user--avatar logout light asleep
brightness-contrast add trash-can copy undo download export launch
arrow--right arrow--left chevron--right chevron--left close edit view
filter renew play stop upload checkmark--filled warning--filled
error--filled information help time document checkmark misuse in-progress
view--off pause chevron--down"

# Icons a stylesheet draws as a background, written as files of their own
# in each theme's icon colour: the arrow of a select.
CSS_ICONS="chevron--down"

case $VERSION in
*[!0-9.]* | "") echo "carbon-fetch: $VERSION is not a version such as 2.68.0" >&2; exit 2 ;;
esac

cd "$(dirname "$0")/.."
OUT=internal/dashboard/web/static/carbon
CDN="https://1.www.s81c.com/common/carbon/web-components/version/v$VERSION"
NPM="https://registry.npmjs.org/@carbon"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM
mkdir "$work/js" "$work/out"

get() { curl -fsSL --proto =https --tlsv1.2 --retry 2 -o "$2" "$1"; }

# Each file, and the files it imports, once. IBM's files import their
# shared parts from the same folder ("./name.js").
queue=""
for c in $COMPONENTS; do queue="$queue $c.min.js"; done
count=0
while [ -n "${queue# }" ]; do
	set -- $queue
	f=$1
	shift
	queue="$*"
	[ -e "$work/js/$f" ] && continue
	case $f in
	*[!A-Za-z0-9._-]* | .*) echo "carbon-fetch: unexpected file name $f" >&2; exit 1 ;;
	esac
	get "$CDN/$f" "$work/js/$f"
	count=$((count + 1))
	for dep in $(grep -oE "(from|import)[[:space:]]*\\(?[[:space:]]*[\"']\\./[^\"']+[\"']" "$work/js/$f" |
		sed -E "s/.*\\.\\/([^\"']+).*/\\1/" | sort -u); do
		[ -e "$work/js/$dep" ] || queue="$queue $dep"
	done
done
echo "carbon-fetch: $count files of @carbon/web-components $VERSION"

# The browser files must not call out: no request to anywhere.
if grep -lE "sendBeacon|XMLHttpRequest|new WebSocket|[^A-Za-z_.]fetch\\(" "$work"/js/*.js; then
	echo "carbon-fetch: the files above can make network requests; look at them before using this version" >&2
	exit 1
fi

for p in "web-components $VERSION" "styles $STYLES" "icons $ICONS"; do
	set -- $p
	get "$NPM/$1/-/$1-$2.tgz" "$work/$1.tgz"
	mkdir "$work/$1"
done
tar -xzf "$work/web-components.tgz" -C "$work/web-components" package/LICENSE
tar -xzf "$work/styles.tgz" -C "$work/styles" package/css/styles.min.css
tar -xzf "$work/icons.tgz" -C "$work/icons" package/svg

go run ./tools/carbonprep -styles "$work/styles/package/css/styles.min.css" -styles-version "$STYLES" \
	-icons "$work/icons/package/svg" -icons-version "$ICONS" -names "$ICON_NAMES" -css-icons "$CSS_ICONS" -out "$work/out"

rm -rf "$OUT"
mkdir -p "$OUT"
cp "$work"/js/*.js "$OUT/"
cp "$work/web-components/package/LICENSE" "$OUT/LICENSE"
cp "$work"/out/*.css "$work"/out/*.svg "$OUT/"
cat >"$OUT/README.md" <<EOF
# IBM Carbon Design System

Made by \`tools/carbon-fetch.sh $VERSION\`; do not edit these files, run the
script again.

- \`*.js\`: IBM's ready files of \`@carbon/web-components\` $VERSION, from
  IBM's CDN, unchanged: the components
  $(echo $COMPONENTS | sed 's/ /, /g'),
  and the shared files they load.
- \`themes.css\`: the themes g10 (light) and g100 (dark) of \`@carbon/styles\`
  $STYLES.
- \`icons.svg\`: icons of \`@carbon/icons\` $ICONS; \`NAME-g10.svg\` and
  \`NAME-g100.svg\`: $CSS_ICONS in each theme's icon colour.

All three are Copyright IBM Corp. under the Apache License 2.0, in
\`LICENSE\`. \`SHA256SUMS\` lists every file, so that a change shows in a
diff.
EOF
(cd "$OUT" && sha256sum -- *.js *.css *.svg LICENSE >SHA256SUMS)
echo "carbon-fetch: wrote $OUT ($(du -sh "$OUT" | cut -f1))"
