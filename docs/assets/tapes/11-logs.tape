Output brag-output/clips/11-logs.mp4
Source docs/assets/tapes/settings.tape
Source docs/assets/tapes/setup.tape
Set TypingSpeed 24ms

Type "setsid blaze serve ./site --port 8002 --log-json >access.log 2>/dev/null &"
Enter
Sleep 1500ms
Type "clear"
Enter
Wait

Show
Sleep 400ms
Type "curl -s -o /dev/null -H 'X-Request-ID: launch-demo' localhost:8002/docs/readme.md"
Sleep 500ms
Enter
Wait
Sleep 800ms
Type "cat access.log"
Sleep 500ms
Enter
Wait
Sleep 2500ms

Hide
Type "pkill blaze; cd ~; rm -rf $D"
Enter
Sleep 500ms
