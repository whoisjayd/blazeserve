Output brag-output/clips/04-serve.mp4
Source docs/assets/tapes/settings.tape
Source docs/assets/tapes/setup.tape

Show
Sleep 400ms
Type "blaze serve ./site --hide '*.env'"
Sleep 500ms
Enter
Wait+Screen /Press Ctrl\+C to stop/
Sleep 3s
Ctrl+C
Wait
Sleep 800ms

Hide
Type "pkill blaze; cd ~; rm -rf $D"
Enter
Sleep 500ms
