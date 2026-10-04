# Cowrie Honeypot

`cowrie.cfg` contains this project's Cowrie settings. Install Cowrie using its official installation guide, then place or merge this configuration at the Cowrie instance's `etc/cowrie.cfg` path. Review paths and enabled output plugins against the installed Cowrie version before starting the service.

Keep the honeypot isolated from production networks. Restrict outbound access, expose only the ports required for collection, and monitor the host because a honeypot receives untrusted input by design.

If using Cowrie's database output plugin, install the schema provided by the official Cowrie setup instructions for the Cowrie version in use. No Cowrie schema is bundled here.