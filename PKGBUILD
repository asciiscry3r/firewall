# Maintainer: Klimenko Maxim Sergievich <klimenkomaximsergievich@gmail.com>
# Contributor: Klimenko Maxim Sergievich <klimenkomaximsergievich@gmail.com>

pkgname=simple-stateful-firewall
pkgver=0.0.15
pkgrel=1
pkgdesc="Simple Stateful Firewall. (GitHub version)"
arch=('i686' 'x86_64')
url="https://github.com/asciiscry3r/firewall"
license=('GPL2')
depends=('iptables')
optdepends=('opensnitch: Web Application Firewall, but please disable his embedded system firewall')
makedepends=('git')
source=('simple-stateful-firewall-$pkgver.tar.gz::https://github.com/asciiscry3r/firewall/archive/refs/tags/$pkgver.tar.gz')
sha1sums=('SKIP')
conflicts=('simple-stateful-firewall')
provides=('simple-stateful-firewall')

package() {
    cd "$pkgname-$pkgver" || exit 1

    make DESTDIR="$pkgdir" install
}
