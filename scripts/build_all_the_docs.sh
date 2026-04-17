#!/bin/bash

set -e

git config --global pull.ff only
DOCS_DIR="/tmp/netidm_docs"

echo "DOCS DIR: ${DOCS_DIR}"
echo "PWD: $(pwd)"

if [ "${GITHUB_ACTIONS}" ]; then
    echo "Running in Github Actions"
    git config user.email "netidm@netidm.com"
    git config user.name "Netidm Github Actions Runner"
fi

git fetch --all

function build_version() {
    BOOK_VERSION=$1
    echo "Book version: ${BOOK_VERSION}"
    echo "<li><a href=\"/netidm/${BOOK_VERSION}\">${BOOK_VERSION}</a></li>" >> "${DOCS_DIR}/index.html"

    if [ "$(git branch --show-current)" != "${BOOK_VERSION}" ]; then
        git switch -c "${BOOK_VERSION}" || git switch "${BOOK_VERSION}"
    fi
    echo "Running mdbook build"
	mdbook build book
    echo "Running cargo doc"
    cargo doc --quiet --no-deps
    echo "Moving book to ${DOCS_DIR}/${BOOK_VERSION}/"
    mv ./book/book/ "${DOCS_DIR}/${BOOK_VERSION}/"
    echo "Cleaning out rustdoc dir..."
    rm -rf "${DOCS_DIR}/${BOOK_VERSION}/rustdoc/"
	echo "Moving rustdoc to ${DOCS_DIR}/${BOOK_VERSION}/rustdoc/"
    mkdir -p "${DOCS_DIR}/${BOOK_VERSION}/rustdoc/"
    mv ./target/doc/* "${DOCS_DIR}/${BOOK_VERSION}/rustdoc/"
}

echo "Cleaning old docs dir"
rm -rf "${DOCS_DIR}"
mkdir -p "${DOCS_DIR}"

cat > "${DOCS_DIR}/index.html" <<-'EOM'
<html>
<head>
<title>netidm docs root</title>
</head>
<body>
<h1>Netidm docs</h1>
<ul>
EOM


LATEST="$(git tag -l 'v*' --sort "-version:refname" | grep -v '1.1.0alpha' | head -n1)"
{
    echo "<li><strong><a href=\"/netidm/master/\">Latest Dev Version</a></strong></li>"
    echo "<li><strong><a href=\"/netidm/stable/\">Latest Stable Version (${LATEST})</a></strong></li>"
} >> "${DOCS_DIR}/index.html"

# build the current head
build_version master

# build all the other versions
for version in $(git tag -l 'v*' --sort "-version:refname" | grep -v '1.1.0alpha'); do
    echo "$version"
    build_version "${version}"
done

cat >> "${DOCS_DIR}/index.html" <<-'EOM'
</ul>
</body>
</html>
EOM
ls -la "${DOCS_DIR}"

rm -rf ./docs/
mv "${DOCS_DIR}" ./docs/
ln -s "${LATEST}" ./docs/stable
