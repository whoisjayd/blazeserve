# Shared by every scene tape. Render from the repository root, one at a time:
#   for t in docs/assets/tapes/[0-9]*.tape; do vhs "$t"; done
# Needs a Linux blaze in ~/.local/bin of the shell VHS starts (WSL on Windows).
# Clips are written to brag-output/clips, which is git-ignored.

Set Shell "bash"
Set FontFamily "Cascadia Mono"
Set FontSize 20
Set Width 2560
Set Height 1350
Set Padding 30
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms
Set Framerate 12
Set CursorBlink false
Set Margin 75
Set MarginFill "docs/assets/demo-bg.png"
Set BorderRadius 17
Set WindowBar Colorful
Set WindowBarSize 30
Set WaitTimeout 90s
Set WaitPattern /\$$/
