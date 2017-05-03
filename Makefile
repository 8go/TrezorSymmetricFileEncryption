UI_GENERATED := \
	ui_trezor_passphrase_dialog.py \
	ui_dialog.py \
	ui_enter_pin_dialog.py \
	ui_trezor_chooser_dialog.py \
	#end of UI_GENERATED

all: $(UI_GENERATED)

ui_%.py: %.ui
	pyuic4 -o $@ $<

clean:
	rm -rf $(UI_GENERATED)
