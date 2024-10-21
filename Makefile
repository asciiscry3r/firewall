
BUILD_DIR=

.PHONY: install
install:
	mkdir -p /etc/systemd/system/NetworkManager-dispatcher.service.d/
	install -Dm0640 simplestatefulfirewall.service /usr/lib/systemd/system/simplestatefulfirewall.service
	install -Dm0640 simplestatefulfirewall.timer /usr/lib/systemd/system/simplestatefulfirewall.timer
	install -Dm0750 simplestatefulfirewall.sh /usr/lib/systemd/system/simplestatefulfirewall.sh
	install -Dm0640 remain_after_exit.conf /etc/systemd/system/NetworkManager-dispatcher.service.d/remain_after_exit.conf
	install -Dm0750 30-restart-firewall.sh /etc/NetworkManager/dispatcher.d/30-restart-firewall.sh
	install -Dm0640 sysctl.conf /etc/sysctl.d/00-sysctl.conf


.PHONY: clean
clean:
	rm -r $(BUILD_DIR)

