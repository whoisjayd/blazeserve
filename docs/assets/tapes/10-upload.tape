Output brag-output/clips/10-upload.mp4
Source docs/assets/tapes/settings.tape
Source docs/assets/tapes/setup.tape
Set TypingSpeed 24ms

Type "setsid blaze serve ./inbox --port 8001 --max-upload-mb 500 --auth-env BLAZE_AUTH >/dev/null 2>&1 &"
Enter
Sleep 1500ms
Type "clear"
Enter
Wait

Show
Sleep 400ms
Type "blaze put site/big.iso http://localhost:8001/ --auth-env BLAZE_AUTH"
Sleep 500ms
Enter
Wait+Screen /Uploaded/
Sleep 1s
Type "ls -lh inbox"
Sleep 500ms
Enter
Wait
Sleep 2500ms

Hide
Type "pkill blaze; cd ~; rm -rf $D"
Enter
Sleep 500ms
