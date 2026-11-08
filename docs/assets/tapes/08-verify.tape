Output brag-output/clips/08-verify.mp4
Source docs/assets/tapes/settings.tape
Source docs/assets/tapes/setup.tape
Set TypingSpeed 24ms

Type "setsid blaze serve ./site --hide '*.env' >/dev/null 2>&1 &"
Enter
Sleep 1500ms
Type "clear"
Enter
Wait

Show
Sleep 400ms
Type "blaze checksum site/big.iso"
Sleep 500ms
Enter
Wait
Sleep 1500ms

Type "curl -s 'localhost:8000/big.iso?hash'"
Sleep 500ms
Enter
Wait
Sleep 2500ms

Hide
Type "pkill blaze; cd ~; rm -rf $D"
Enter
Sleep 500ms
