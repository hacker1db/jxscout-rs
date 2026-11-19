# Record with: vhs demo.tape   (needs `cargo build --release` first)
Output docs/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1400
Set Height 820
Set Padding 16
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms

Hide
Type `export PATH="$PWD/target/release:$PATH" OUT="$(mktemp -d)" PS1='$ '` Enter
Type "(demo/serve-fixtures.sh >/dev/null 2>&1 &) ; sleep 1 ; clear" Enter
Sleep 1500ms
Show

Type "# 1) Standalone ingest: fetch a URL list, discover chunks + source maps" Enter
Sleep 300ms
Type `jxscout-rs --output-dir $OUT -p demo --allow-private-targets --rate-limit-rps 0 ingest-urls demo/urls.txt 2>/dev/null` Enter
Sleep 2500ms
Type `(cd $OUT/demo && find . -type f | sort)` Enter
Sleep 2500ms
Type `jxscout-rs --output-dir $OUT -p demo findings --category "Client Behavior" 2>/dev/null | sed "s#http://127.0.0.1:8765##"` Enter
Sleep 4s
Type "clear" Enter
Type "# 2) Live: TUI + ingest endpoint; a proxy plugin POSTs captured traffic" Enter
Sleep 300ms
Type "demo/live.sh" Enter
Sleep 9s
Type "g"
Sleep 800ms
Down
Sleep 500ms
Down
Sleep 500ms
Down
Sleep 500ms
Down
Sleep 2500ms
Tab
Sleep 500ms
Down
Sleep 500ms
Down
Sleep 1500ms
Type "?"
Sleep 2s
Down
Down
Down
Sleep 1s
Escape
Sleep 500ms
Tab
Tab
Type "/"
Type "chunk"
Enter
Sleep 2500ms
Type "q"
Sleep 1s
