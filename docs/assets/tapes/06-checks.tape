Output brag-output/clips/06-checks.mp4
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
Type "curl -si -r 0-17 localhost:8000/docs/readme.md"
Sleep 500ms
Enter
Wait
Sleep 1800ms

Type "curl -s -o /dev/null -w 'hidden .env      -> %{http_code}\n' localhost:8000/.env"
Sleep 500ms
Enter
Wait
Sleep 1200ms

Type "curl -s -o /dev/null -w 'path traversal  -> %{http_code}\n' --path-as-is localhost:8000/../etc/passwd"
Sleep 500ms
Enter
Wait
Sleep 2500ms

Hide
Type "pkill blaze; cd ~; rm -rf $D"
Enter
Sleep 500ms
