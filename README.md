# Thor

Rotate passwords in hashicorp vault based on

- ex employee - User has left the company and credentials they have accessed need to be changed
- compromised password - A password used on company systems has been discovered in the wild and needs to be changed

This platform requires [Seth Vargos Password Generator Plugin for Hashicorp Vault](https://github.com/sethvargo/vault-secrets-gen) to be installed

## Build
Build should be done from a linux environment - this will cross compile the Windows binary.

```
make build
```

## Install

### Server
> The server component should only be run on a Linux machine. It is not possible to run the server as a Windows service.

- Copy the thor binary to a location in $PATH
- Create the data directory `/data`
- Create the config file `/data/config.yaml` - note, short form extension `.yml` is currently not supported

Add a firewall rule to allow inbound TCP port 9100

```
# iptables -A INPUT -p tcp -m tcp --dport 9100 -m state --state NEW -j ACCEPT
```

Create a systemd config file and place this at /usr/lib/systemd/system then enable it and start the service

**thor.service**
```
[Unit]
Description=Thor Credential Management
After=syslog.target network.target

[Service]
ExecStart=/usr/bin/thor server
ExecReload=/bin/kill -SIGINT "$MAINPID"
PIDFile=/var/run/thor.pid
Restart=always
RestartSec=120

[Install]
WantedBy=multi-user.target
```

### Trust ShaSums
Before installing any agent, the server must be instructed to trust the SHASums of the newly built binary packages. Each
time these packages are rebuilt, these must be added into the database before they can be used in a live environment.

```
linux=$(sha256sum thor | awk '{print $1}')
windows=$(sha256sum thor.exe | awk '{print $1}')
curl -kvvvL -H 'Content-Type: application/json' -d '{"shas":[{"sha":"$linux","name":"thor"},{"sha":"$windows","name":"thor.exe"}]}' https://localhost:9100/api/v1/shasum
```

### Add IPs of agents
Any agent that connects, must be trusted by Thor. To do this, you need to call the `adddevices` endpoint with a list of
devices that should be let in.

> Note, this is different from the list of trusted devices in the config file. You should not mix the two.

```
curl -kvvvL -H 'Content-Type: application/json' -d '{"devices":["192.168.1.5", "192.168.1.6" ...]}' https://localhost:9100/api/v1/adddevices
```

### Linux agent
> Warning: If you have a custom CA on either thor or Vault, the device must trust the CA before the agent is started.
>
> This is applicable to both Windows and Linux agents

Copy the binary to the device
Create an agent config file `/data/agent.yaml` # todo - move to /etc
Add a firewall rule to allow UDP port 7468 through the firewall

```
# iptables -A INPUT -p udp -m udp --dport 7468 -m state --state NEW -j ACCEPT
```

As root, run `thor agent install`

This will install a service script in /usr/lib/systemd/system and start the service
the agent can then be viewed in the Journal logs

```
journalctl -fu thor-agent
```

### Windows agent
Copy thor.exe to the device and place it in C:\Program Files\thor
Create an agent.yaml
Add a firewall rule to allow UDP port 7468 through the firewall
run `thor agent install` to install the Windows service
Check the service is started.


## Example agent.yaml
```yaml
agent:
  thorServer: https://thor.example.com:9100
  vaultServer: https://vault.example.com
  namespace: ""
  paths:
    - kv/devices/myserver # kv version 1
    - kv2/data/devices/myserver # kv version 2
```

Multiple paths may be specified with the agent overwriting passwords as it reads the list

> Note: When rotating passwords, the tokens supplied to the agent are protected by policy specific to the paths
> discovered during the last search operation.
>
> This means that the agent may try to access paths that are denied by policy with the agent ignoring any errors
> which may arise.
>
> Where an agent is configured to read multiple paths and more than 1 of those paths contains a credential for an
> account the server is managing, it is possible to end up in a situation whereby any path in vault may contain an
> active password to a device whilst other paths do not.
>
> It is wise to structure Vault trees in such a way that a device password is only ever stored in a single location
> and no other paths given to the agent contain conflicting information
>
> For example:
>
> agent.yaml
> ```
> agent:
>   thorServer
>   vaultServer
>   namespace:
>   paths:
>     - secret/data/devices/myserver
>     - secret/data/devices/anotherserver
> ```
>
> secret/data/devices/myserver
> ```
> administrator: abcdef
> ```
>
> secret/data/devices/anotherserver
> ```
> administrator: 123456
> ```

