Output brag-output/clips/05-headers.mp4
Source docs/assets/tapes/settings.tape
Source docs/assets/tapes/setup.tape

Type "setsid blaze serve ./site --hide '*.env' >/dev/null 2>&1 &"
Enter
Sleep 1500ms
Type "clear"
Enter
Wait

Show
Sleep 400ms
Type "curl -sI localhost:8000/big.iso"
Sleep 500ms
Enter
Wait
Sleep 4s

Hide
Type "pkill blaze; cd ~; rm -rf $D"
Enter
Sleep 500ms
