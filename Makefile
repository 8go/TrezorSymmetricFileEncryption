UI_GENERATED := \
	ui_trezor_chooser_dialog.py \
	ui_trezor_pin_dialog.py \
	ui_trezor_passphrase_dialog.py \
	ui_dialog.py \
	#end of UI_GENERATED

all: $(UI_GENERATED)

ui_%.py: %.ui
	pyuic5 -o $@ $<

clean:
	rm -f $(UI_GENERATED)
	rm -rf __pycache__
	rm -f *.pyc
