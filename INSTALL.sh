#!/usr/bin/env bash

function install_simplestatefullfirewall {
  cp simplestatefullfirewall.service /usr/lib/systemd/system/simplestatefullfirewall.service
  cp simplestatefullfirewall.timer /usr/lib/systemd/system/simplestatefullfirewall.timer
  cp simplestatefullfirewall.sh /usr/bin/simplestatefullfirewall.sh
  chmod 640 /usr/lib/systemd/system/simplestatefullfirewall.service
  chmod 640 /usr/lib/systemd/system/simplestatefullfirewall.timer
  chmod u=rwx,g=rx /usr/bin/simplestatefullfirewall.sh
  systemctl daemon-reload
}

if [ ! -f /usr/lib/systemd/system/simplestatefullfirewall.service ]; then
    install_simplestatefullfirewall
fi

if [ ! -f /usr/lib/systemd/system/simplestatefullfirewall.timer ]; then
    install_simplestatefullfirewall
    systemctl start simplestatefullfirewall.timer
    systemctl enable simplestatefullfirewall.timer
else
    systemctl start simplestatefullfirewall.timer
    systemctl enable simplestatefullfirewall.timer
fi

if [ ! -f /usr/bin/simplestatefullfirewall.sh ]; then
    install_simplestatefullfirewall
fi
