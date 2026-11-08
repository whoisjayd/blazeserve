Output brag-output/clips/09-metrics.mp4
Source docs/assets/tapes/settings.tape
Source docs/assets/tapes/setup.tape

Type "setsid blaze serve ./site --hide '*.env' >/dev/null 2>&1 &"
Enter
Sleep 1500ms
Type "for i in 1 2 3; do curl -s -o /dev/null localhost:8000/docs/readme.md; done; curl -s -o /dev/null -r 0-99 localhost:8000/big.iso"
Enter
Sleep 1s
Type "clear"
Enter
Wait

Show
Sleep 400ms
Type "curl -s localhost:8000/__metrics__"
Sleep 500ms
Enter
Wait
Sleep 5s

Hide
Type "pkill blaze; cd ~; rm -rf $D"
Enter
Sleep 500ms
