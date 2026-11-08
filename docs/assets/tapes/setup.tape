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
