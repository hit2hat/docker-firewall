# Docker Firewall Operator
A declarative, label-based firewall for Docker containers.

Instead of fighting with Docker daemon over host `iptables` rules (which Docker frequently overwrites),
this operator injects nftables rules directly into the isolated Network Namespace (netns) of each container.
This ensures that your container network restrictions are persistent, secure, and independent of the host's firewall configuration.

## Features
* Declarative Configuration: Manage firewall rules directly via docker-compose.yaml labels. 
* True Isolation: Rules are applied inside the container's netns, making them completely immune to host Docker network reloads. 
* Dynamic DNS Resolution: Supports standard Docker service names (and Swarm tasks.*). IP addresses are resolved using Docker's internal DNS (127.0.0.11) and updated automatically on the fly. 
* High Performance: Uses Netlink and nftables Sets under the hood. Rules are updated instantly via diffing without dropping legitimate traffic or flushing the entire ruleset.

## How to use

### Deploymnet
The operator runs as a Docker container itself. However, to manipulate the network namespaces of other containers, it requires specific privileges.
```yaml
services:
    firewall-operator:
        restart: unless-stopped
        image: ghcr.io/hit2hat/firewall-operator:latest
        pid: "host"           # Required to discover processes and their netns on the host
        cap_add:
            - NET_ADMIN       # Required to manage network namespaces and nftables
            - SYS_ADMIN       # Required to switch namespaces (setns)
            - SYS_PTRACE      # Required to inspect processes
        cap_drop:
            - ALL             # Drop all other unneeded privileges for security
        volumes:
            - /var/run/docker.sock:/var/run/docker.sock:ro # Required to listen to Docker API
```

### Available labels
You can control the firewall behavior for any container by adding the following labels:

| Label                   | Description                                                                                                 | Example                     |
|:------------------------|:------------------------------------------------------------------------------------------------------------|:----------------------------|
| `firewall.enabled`      | Enables the firewall operator for this container.                                                           | `true` or `false`           |
| `firewall.ports`        | Comma-separated list of ports exposed to the outside. All other ports are dropped at the very first filter. | `80,443,8080`               |
| `firewall.in.enabled`   | Enables filtering for incoming traffic.                                                                     | `true` or `false`           |
| `firewall.in.mode`      | Defines the behavior for incoming traffic (`whitelist` or `blacklist`).                                     | `whitelist`                 |
| `firewall.in.source`    | Comma-separated list of allowed/blocked incoming IP addresses/subnets.                                      | `192.168.1.100,10.0.0.0/24` |
| `firewall.in.services`  | Comma-separated list of allowed/blocked internal Docker services.                                           | `nginx,api-gateway`         |
| `firewall.out.enabled`  | Enables filtering for outgoing traffic.                                                                     | `true` or `false`           |
| `firewall.out.mode`     | Defines the behavior for outgoing traffic (`whitelist` or `blacklist`).                                     | `whitelist`                 |
| `firewall.out.source`   | Comma-separated list of allowed/blocked outgoing external IPs.                                              | `8.8.8.8,1.1.1.1`           |
| `firewall.out.services` | Comma-separated list of allowed/blocked destination Docker services.                                        | `postgres,redis`            |

### Example usage
Here is an example of two services. test2 is allowed to send traffic only to test1.
Any other outgoing traffic from test2 will be dropped. test1 accepts incoming traffic only from test2 on port 80.

```yaml
services:
  test1:
    image: nginx:alpine
    labels:
      - "firewall.enabled=true"
      - "firewall.ports=80"
      - "firewall.in.enabled=true"
      - "firewall.in.mode=whitelist"
      - "firewall.in.services=test2"

  test2:
    image: curlimages/curl:latest
    command: ["sleep", "infinity"]
    labels:
      - "firewall.enabled=true"
      - "firewall.out.enabled=true"
      - "firewall.out.mode=whitelist"
      - "firewall.out.services=test1"
```

## How to build
If you want to build the binary from source, ensure you have Go installed, then run:

### For amd64:
`GOOS=linux GOARCH=amd64 go build -o build/firewall_amd64 src/main.go`

### For arm64:
* arm64: `GOOS=linux GOARCH=arm64 go build -o build/firewall_arm64 src/main.go`

## License
MIT.
