# PS4HEN
PS4 Homebrew ENabler for version 4.55 based on Flatz writeup and using IDC's fake codebase

You can find his codebase here https://github.com/idc/ps4-fake-405
aswell as his method to patch shellcore here https://github.com/idc/ps4-experiments-405

to make, do as follows in your terminal:

	cd PS4HEN/payload
	make
	cd ../PS4HEN
	bash convert_payload.sh
	make
	
to run, do as follows in your terminal:

	cd PS4HEN/PS4HEN
	socat -u FILE:PS4HEN.BIN TCP:<ps4 ip>:9020

To Do:

	make and automation script to do the above for you lol
	
# Credits
Thanks to these devs in helping in the process

flat_z<br/>
idc<br/>
zecoxao<br/>
psxdev<br/>
	
