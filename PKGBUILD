# Maintainer: Klimenko Maxim Sergievich <klimenkomaximsergievich@gmail.com>
# Contributor: Klimenko Maxim Sergievich <klimenkomaximsergievich@gmail.com>

pkgname=simple-stateful-firewall
pkgver=1
pkgrel=1
pkgdesc="Simple Stateful Firewall. (GitHub version)"
arch=('i686' 'x86_64')
url="https://github.com/asciiscry3r/firewall"
license=('GPL2')
depends=('iptables')
optdepends=('opensnitch: Web Application Firewall')
makedepends=('git')
source=('aur::git+https://github.com/asciiscry3r/firewall')
sha1sums=('SKIP')
conflicts=('simple-stateful-firewall')
provides=('simple-stateful-firewall')

_branch=aur

pkgver() {
    cd "${_branch}"
    printf "%s" "${pkgver}"
}

package() {
    cd "${_branch}"

}
