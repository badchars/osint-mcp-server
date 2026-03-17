# VHS Demo — osint-mcp-server
Output .github/demo.gif

Set Shell "bash"
Set FontSize 14
Set Width 900
Set Height 550
Set Theme "Catppuccin Mocha"
Set Padding 20
Set TypingSpeed 35ms

# List all tools
Type `npx osint-mcp-server --list`
Sleep 300ms
Enter
Sleep 5s

# DNS lookup
Type `npx osint-mcp-server --tool dns_lookup '{"domain":"example.com","type":"A"}'`
Sleep 300ms
Enter
Sleep 5s

# Email security check
Type `npx osint-mcp-server --tool dns_email_security '{"domain":"example.com"}' --format text`
Sleep 300ms
Enter
Sleep 8s

Sleep 3s
