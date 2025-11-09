# wg-webui
Simple webinterface for WireGuard to manage peers

# Features
 - Add & delete peers
 - LAN & all traffic configuration file generation
 - Show QR codes for peer configuration files
 - Download configuration files as a `.conf` file
 - Download peer config files as a `.zip` bundle

# Installing / running
1. Install dependencies with using `uv sync`
2. Create `peer-data` folder
3. Run using `uv run -- flask run`

This app needs passwordless `sudo` access for the following commands: `wg`, `wg-quick`, `ip`.<br>
Example file `/etc/sudoers.d/wg-access` (gives user `user` access to the neccesary commands via `sudo`):

```
user ALL=(root) NOPASSWD: /usr/bin/wg, /usr/bin/wg-quick, /usr/bin/ip
```

# Disclaimer
I am not a webdev, I am actually not a software developer at all so this might be the most unsecured piece of software on earth.  
Use responsibly, don't be an idiot and make the webinterface available to the whole internet or something.  

This is just a small pet project that I made. I also don't really like developing webapps, so don't expect me to fix bugs that you might find. PRs are welcome, but again, I might take a long time to merge them.
