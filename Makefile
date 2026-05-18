# Run once after cloning to enable the local pre-push quality gate.
install-hooks:
	chmod +x .githooks/pre-push
	git config core.hooksPath .githooks
