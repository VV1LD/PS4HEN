# PS4HEN
PS4 Homebrew ENabler for version 4.05 based on Flatz writeup and using IDC's codebase

You can find his codebase here https://github.com/idc/ps4-fake-405
aswell as his method to patch shellcore here https://github.com/idc/ps4-experiments-405

First this payload needs to have ps4-payload-sdk compiled and set as and Env variable

you can find it here: https://github.com/idc/ps4-payload-sdk

when compiled and env variable set to PS4SDK you can compile PS4HEN as a binary!
follow instructions in PS4-SDK or ps4-payload-sdk to do this..

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

	make an automation script to do the above for you lol
	
