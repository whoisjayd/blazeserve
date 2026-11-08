# BlazeServe terminal demo.
#
# Render from the repository root:  vhs docs/assets/demo.tape
# Needs a Linux `blaze` in ~/.local/bin of the shell VHS starts. On Windows,
# `Set Shell "bash"` is WSL, so build or copy the Linux binary there first.
#
# The canvas is deliberately large (3072x1620) so long outputs fit untrimmed and the
# result can be cropped or zoomed later without losing sharpness. Everything that is not
# part of the story (setup, background servers, cleanup) runs between Hide and Show.

Output blaze-terminal.mp4

Set Shell "bash"
Set FontFamily "Cascadia Mono"
Set FontSize 24
Set Width 3072
Set Height 1620
Set Padding 36
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Framerate 30
Set PlaybackSpeed 0.8
Set CursorBlink false
Set Margin 90
Set MarginFill "docs/assets/demo-bg.png"
Set BorderRadius 20
Set WindowBar Colorful
Set WindowBarSize 36
Set WaitTimeout 90s
Set WaitPattern /\$$/

# Hidden setup: quiet shell, amber prompt, a scratch folder with a 160 MB file.
Hide
Type "set +m; trap '' TTOU TTIN TSTP"
Enter
Sleep 300ms
Type "export PATH=$HOME/.local/bin:$PATH PS1='\[\e[38;2;245;165;36m\]$\[\e[0m\] ' BLAZE_AUTH=ada:s3cret"
Enter
Type "D=$(mktemp -d) && cd $D && mkdir -p site/docs inbox && head -c 160M /dev/urandom > site/big.iso && echo '# BlazeServe demo' > site/docs/readme.md && echo SECRET=1 > site/.env"
Enter
Type "clear"
Enter
Wait
Show

Sleep 800ms
Type "blaze version"
Sleep 500ms
Enter
Wait
Sleep 4s

Hide
Type "clear"
Enter
Wait
Show

Type "blaze --help"
Sleep 500ms
Enter
Wait
Sleep 10s

Hide
Type "clear"
Enter
Wait
Show

Type "blaze doctor ./site"
Sleep 500ms
Enter
Wait
Sleep 5s

Hide
Type "clear"
Enter
Wait
Show

Type "blaze serve ./site --hide '*.env'"
Sleep 500ms
Enter
Wait+Screen /Press Ctrl\+C to stop/
Sleep 5s
Ctrl+C
Wait
Sleep 1s

# Hidden: start the servers the next scenes talk to, with their output discarded.
Hide
Type "setsid blaze serve ./site --hide '*.env' >/dev/null 2>&1 &"
Enter
Type "setsid blaze serve ./inbox --port 8001 --max-upload-mb 500 --auth-env BLAZE_AUTH >/dev/null 2>&1 &"
Enter
Type "setsid blaze serve ./site --port 8002 --log-json >access.log 2>/dev/null &"
Enter
Sleep 2s
Type "clear"
Enter
Wait
Show

Type "curl -sI localhost:8000/big.iso"
Sleep 500ms
Enter
Wait
Sleep 9s

Hide
Type "clear"
Enter
Wait
Show

Type "curl -si -r 0-17 localhost:8000/docs/readme.md"
Sleep 500ms
Enter
Wait
Sleep 6s

Type "curl -s -o /dev/null -w 'hidden .env      -> %{http_code}\n' localhost:8000/.env"
Sleep 500ms
Enter
Wait
Sleep 2s

Type "curl -s -o /dev/null -w 'path traversal  -> %{http_code}\n' --path-as-is localhost:8000/../etc/passwd"
Sleep 500ms
Enter
Wait
Sleep 5s

Hide
Type "clear"
Enter
Wait
Show

Type "blaze get http://localhost:8000/big.iso --limit-rate 25M"
Sleep 500ms
Enter
Sleep 4s
Ctrl+C
Sleep 1s
Type "ls -lh"
Sleep 500ms
Enter
Wait
Sleep 5s

Type "blaze get http://localhost:8000/big.iso --limit-rate 25M"
Sleep 500ms
Enter
Wait+Screen /Saved big.iso/
Sleep 3s
Type "ls -lh"
Sleep 500ms
Enter
Wait
Sleep 4s

Hide
Type "clear"
Enter
Wait
Show

Type "blaze checksum big.iso"
Sleep 500ms
Enter
Wait
Sleep 3s

Type "curl -s 'localhost:8000/big.iso?hash'"
Sleep 500ms
Enter
Wait
Sleep 7s

Hide
Type "clear"
Enter
Wait
Show

Type "curl -s localhost:8000/__metrics__"
Sleep 500ms
Enter
Wait
Sleep 9s

Hide
Type "clear"
Enter
Wait
Show

Type "blaze put big.iso http://localhost:8001/ --auth-env BLAZE_AUTH"
Sleep 500ms
Enter
Wait+Screen /Uploaded/
Sleep 2s
Type "ls -lh inbox"
Sleep 500ms
Enter
Wait
Sleep 5s

Hide
Type "clear"
Enter
Wait
Show

Type "curl -s -o /dev/null -H 'X-Request-ID: launch-demo' localhost:8002/docs/readme.md"
Sleep 500ms
Enter
Wait
Sleep 1s
Type "cat access.log"
Sleep 500ms
Enter
Wait
Sleep 8s

Hide
Type "clear"
Enter
Wait
Show

Type "blaze telemetry status"
Sleep 500ms
Enter
Wait
Sleep 6s

Type "echo '  docs -> https://github.com/whoisjayd/blazeserve'"
Sleep 500ms
Enter
Wait
Screenshot brag-output/terminal-poster.png
Sleep 6s

# Hidden cleanup.
Hide
Type "pkill blaze; cd ~; rm -rf $D"
Enter
Sleep 1s
