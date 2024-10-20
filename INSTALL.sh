#!/usr/bin/env bash

function install_simplestatefulfirewall {
  yes | sudo cp -rf simplestatefulfirewall.service /usr/lib/systemd/system/simplestatefulfirewall.service
  yes | sudo cp -rf simplestatefulfirewall.timer /usr/lib/systemd/system/simplestatefulfirewall.timer
  yes | sudo cp -rf simplestatefulfirewall.sh /usr/bin/simplestatefulfirewall.sh
  chmod 0640 /usr/lib/systemd/system/simplestatefulfirewall.service
  chmod 0640 /usr/lib/systemd/system/simplestatefulfirewall.timer
  chmod u=rwx,g=rx /usr/bin/simplestatefulfirewall.sh
  systemctl daemon-reload
}

if [ ! -f /usr/lib/systemd/system/simplestatefulfirewall.service ]; then
    install_simplestatefulfirewall
fi

if [ ! -f /usr/lib/systemd/system/simplestatefulfirewall.timer ]; then
    install_simplestatefulfirewall
    systemctl start simplestatefulfirewall.timer
    systemctl enable simplestatefulfirewall.timer
else
    systemctl start simplestatefulfirewall.timer
    systemctl enable simplestatefulfirewall.timer
fi

if [ ! -f /usr/bin/simplestatefulfirewall.sh ]; then
    install_simplestatefulfirewall
fi
