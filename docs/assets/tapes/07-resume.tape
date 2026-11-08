Output brag-output/clips/07-resume.mp4
Source docs/assets/tapes/settings.tape
Source docs/assets/tapes/setup.tape
Set TypingSpeed 22ms

Type "setsid blaze serve ./site --hide '*.env' >/dev/null 2>&1 &"
Enter
Sleep 1500ms
Type "clear"
Enter
Wait

Show
Sleep 400ms
Type "blaze get http://localhost:8000/big.iso --limit-rate 25M"
Sleep 500ms
Enter
Sleep 3s
Ctrl+C
Sleep 1s
Type "ls -lh"
Sleep 500ms
Enter
Wait
Sleep 1800ms

Type "blaze get http://localhost:8000/big.iso --limit-rate 25M"
Sleep 500ms
Enter
Wait+Screen /Saved big.iso/
Sleep 1s
Type "ls -lh"
Sleep 500ms
Enter
Wait
Sleep 2500ms

Hide
Type "pkill blaze; cd ~; rm -rf $D"
Enter
Sleep 500ms
