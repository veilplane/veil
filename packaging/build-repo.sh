#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-ALv2
# Copyright 2026 Julian Siebert. See LICENSE.md.
#
# Builds the static package repository that GitHub Pages serves:
#
#   packaging/build-repo.sh POOL SITE BASE_URL
#
# POOL holds the .deb and .rpm files of every version the repository keeps, SITE is created
# fresh, BASE_URL is where SITE will be served (for the install instructions). The signing key
# must be the only secret key in the GPG keyring; its passphrase comes from GPG_PASSPHRASE.
#
#   SITE/veil-packages.asc          the public key that signs packages and metadata
#   SITE/deb/                       a flat apt repository: Packages, Release, InRelease, Release.gpg
#   SITE/rpm/{x86_64,aarch64}/      dnf/yum repositories, repodata/repomd.xml signed (.asc)
#   SITE/rpm/veil.repo              the .repo file for /etc/yum.repos.d
#   SITE/install.sh                 installs veil from here and joins the node (packaging/install.sh)
#   SITE/index.html                 how to use it, with a link to the legal notice
#   SITE/{legal,imprint,privacy}/   redirects to https://veilplane.com/legal
#
# Needs apt-ftparchive (apt-utils), createrepo_c and gpg.
set -euo pipefail

if [ $# -ne 3 ]; then
	echo "usage: $0 POOL SITE BASE_URL" >&2
	exit 2
fi
pool=$(realpath "$1")
site=$2
base=${3%/}

sign() {
	printf '%s' "${GPG_PASSPHRASE:-}" | gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 "$@"
}

shopt -s nullglob
debs=("$pool"/*.deb)
rpms=("$pool"/*.rpm)
if [ ${#debs[@]} -eq 0 ] || [ ${#rpms[@]} -eq 0 ]; then
	echo "no .deb or .rpm files in $pool" >&2
	exit 1
fi

rm -rf "$site"
mkdir -p "$site/deb" "$site/rpm"
site=$(realpath "$site")
touch "$site/.nojekyll" # serve every file as it is
cp "$(dirname "$0")/install.sh" "$site/install.sh"
gpg --batch --armor --export > "$site/veil-packages.asc"

# apt: a flat repository ("deb URL ./"), one Packages file for both architectures.
cp "${debs[@]}" "$site/deb/"
(
	cd "$site/deb"
	apt-ftparchive packages . > Packages
	gzip -9kn Packages
	apt-ftparchive \
		-o APT::FTPArchive::Release::Origin=Veilplane \
		-o APT::FTPArchive::Release::Label=Veilplane \
		-o APT::FTPArchive::Release::Suite=stable \
		-o APT::FTPArchive::Release::Codename=stable \
		-o APT::FTPArchive::Release::Architectures="amd64 arm64" \
		-o APT::FTPArchive::Release::Description="The veil agent" \
		release . > "$site/Release.tmp" # not in ., or it would list itself
	mv "$site/Release.tmp" Release
	sign --clearsign --output InRelease Release
	sign --armor --detach-sign --output Release.gpg Release
	gpg --batch --verify InRelease
	gpg --batch --verify Release.gpg Release
)

# dnf/yum: one repository per architecture ($basearch).
for arch in x86_64 aarch64; do
	dir="$site/rpm/$arch"
	mkdir -p "$dir"
	files=("$pool"/*."$arch".rpm)
	[ ${#files[@]} -gt 0 ] && cp "${files[@]}" "$dir/"
	createrepo_c --quiet "$dir"
	sign --armor --detach-sign --output "$dir/repodata/repomd.xml.asc" "$dir/repodata/repomd.xml"
	gpg --batch --verify "$dir/repodata/repomd.xml.asc" "$dir/repodata/repomd.xml"
done

cat > "$site/rpm/veil.repo" <<EOF
[veil]
name=veil
baseurl=$base/rpm/\$basearch
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=$base/veil-packages.asc
EOF

cat > "$site/index.html" <<EOF
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>veil packages</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 46rem; margin: 2rem auto; padding: 0 1rem; }
  footer { margin-top: 3rem; font-size: .875rem; }
  pre { overflow-x: auto; padding: .75rem 1rem; border: 1px solid #8884; border-radius: 6px; }
</style>
</head>
<body>
<h1>veil packages</h1>
<p>Packages and repository metadata are signed with <a href="veil-packages.asc">this key</a>.
Source and releases: <a href="https://github.com/veilplane/veil">github.com/veilplane/veil</a>.</p>
<h2>In one step</h2>
<p>Adds the repository below (apt or dnf), installs veil and joins the node:</p>
<pre>curl -fsSL $base/install.sh | sudo sh -s -- join &lt;join code&gt;</pre>
<p>Or <code>-- try</code> for a trial cluster without an account, or no arguments to install only.</p>
<h2>Debian, Ubuntu</h2>
<pre>sudo install -d -m 0755 /etc/apt/keyrings
sudo curl -fsSLo /etc/apt/keyrings/veil.asc $base/veil-packages.asc
echo "deb [signed-by=/etc/apt/keyrings/veil.asc] $base/deb ./" | sudo tee /etc/apt/sources.list.d/veil.list
sudo apt update &amp;&amp; sudo apt install veil</pre>
<h2>Fedora, RHEL, Rocky, Alma</h2>
<pre>sudo curl -fsSLo /etc/yum.repos.d/veil.repo $base/rpm/veil.repo
sudo dnf install veil</pre>
<p>Then put the agent's configuration in <code>/etc/veil/agent.json</code> and run
<code>sudo systemctl enable --now veil</code>.</p>
<footer><a href="https://veilplane.com/legal">Legal notice and privacy</a></footer>
</body>
</html>
EOF

# /legal and /imprint lead to the legal notice and privacy policy of veilplane.com.
for page in legal imprint privacy; do
	mkdir -p "$site/$page"
	cat > "$site/$page/index.html" <<'EOF'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Legal notice and privacy</title>
<meta http-equiv="refresh" content="0; url=https://veilplane.com/legal">
<link rel="canonical" href="https://veilplane.com/legal">
</head>
<body><p><a href="https://veilplane.com/legal">veilplane.com/legal</a></p></body>
</html>
EOF
done

echo "repository in $site:"
(cd "$site" && find . -type f ! -name '*.deb' ! -name '*.rpm' | sort)
