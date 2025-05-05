# lws

**lws** is a Command-Line Interface (CLI) tool designed to streamline the management of Proxmox Virtual Environments (VE), LXC containers, and Docker services through a unified, efficient interface.

[![asciicast](https://asciinema.org/a/8rE7H67VjQ15HQ9KtsJVMRR4O.svg)](https://asciinema.org/a/8rE7H67VjQ15HQ9KtsJVMRR4O)

## Table of Contents
- [Introduction](#introduction)
- [Features](#features)
- [Getting Started](#getting-started)
- [Usage](#usage)
  - [Proxmox Host Management](#proxmox-host-management)
  - [LXC Container Management](#lxc-container-management)
  - [Docker Management](#docker-management)
  - [Container Backups & Restores](#container-backups--restores)
  - [Monitoring & Reporting](#monitoring--reporting)
  - [Security Tools](#security-tools)
  - [Managing Scaling Thresholds and Triggers](#managing-scaling-thresholds-and-triggers)
- [Security Considerations](#security-considerations)
- [Best Practices](#best-practices)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## Introduction

**lws** (Linux Web Services) is an open-source CLI tool designed to help developers and system administrators manage Proxmox environments, LXC containers, and Docker services with a unified, AWS-like interface. It simplifies complex operations, reducing them to single commands that can be executed locally or remotely.

## Features

### General

- **Unified Interface**: Manage Proxmox hosts, LXC containers, and Docker services with a single tool
- **Remote Operations**: Execute commands locally or remotely via SSH
- **Error Handling**: Robust error detection and reporting
- **Logging**: Comprehensive logging with both text and JSON formats
- **Command Alias Support**: Use short aliases for common commands

### Proxmox Management

- **Host Monitoring**: Monitor CPU, memory, and disk usage of Proxmox hosts
- **Cluster Operations**: Manage Proxmox clusters (start, stop, restart)
- **Template Management**: Upload, create, and delete LXC templates
- **Firewall Rules**: Define and manage security groups and firewall rules
- **Host Backups**: Create and manage backups of Proxmox configurations

### LXC Container Management

- **Container Operations**: Create, start, stop, reboot, and destroy containers
- **Resource Scaling**: Dynamically adjust CPU, memory, and storage resources
- **Snapshot Management**: Create, list, and restore container snapshots
- **Network Configuration**: Configure network settings for containers
- **Volume Management**: Attach and detach storage volumes to containers
- **Container Migration**: Migrate containers between Proxmox hosts
- **Clone Containers**: Create identical copies of existing containers
- **Command Execution**: Run arbitrary commands within containers
- **Network Testing**: Test network connectivity from containers
- **Backup & Restore**: Create and restore container backups

### Docker Management

- **Installation**: Install Docker and Docker Compose within LXC containers
- **Container Operations**: Run, stop, and manage Docker containers
- **Application Deployment**: Deploy applications using Docker Compose
- **Log Access**: View logs from Docker containers
- **Container Listing**: List running Docker containers
- **Application Updates**: Update applications with new images

### Security Tools

- **Security Scanning**: Perform security audits on containers
- **Network Discovery**: Discover reachable hosts in container networks
- **Health Checks**: Perform health checks with automatic issue detection
- **Monitoring**: Monitor real-time resource usage with thresholds

### Resource Reporting

- **Advanced Container Reports**: Generate comprehensive reports on container status and resources
- **Resource Monitoring**: Real-time monitoring of container CPU, memory, and disk usage
- **Scaling Recommendations**: Get intelligent scaling suggestions based on usage patterns

## Getting Started

### Prerequisites

- Python 3.6 or higher
- Proxmox Virtual Environment 6.x or higher
- SSH access to Proxmox hosts
- The following Python packages:
  - click
  - pyyaml
  - requests
  - tqdm

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/lws.git
cd lws
```

2. Install required Python packages:
```bash
pip install -r requirements.txt
```

3. Create a configuration file `config.yaml` with your Proxmox server details:
```yaml
regions:
  eu-south-1:
    availability_zones:
      az1:
        host: proxmox1.example.com
        user: root
        ssh_password: your_password
      az2:
        host: proxmox2.example.com
        user: root
        ssh_password: your_password

instance_sizes:
  small:
    memory: 512
    cpulimit: 1
    storage: local:8
  medium:
    memory: 1024
    cpulimit: 2
    storage: local:16
  large:
    memory: 2048
    cpulimit: 4
    storage: local:32

default_storage: local
default_network: vmbr0
use_local_only: false
```

4. Make the script executable and create an alias:
```bash
chmod +x lws.py && alias lws='python3 /path/to/lws.py'
```

5. Verify the installation:
```bash
lws --version
```

## Usage

### Proxmox Host Management

#### List Proxmox Hosts
```bash
lws px list
```

#### Check Host Status
```bash
lws px status --region eu-south-1 --az az1
```

#### List Clusters
```bash
lws px clusters --region eu-south-1 --az az1
```

#### Backup Proxmox Configuration
```bash
lws px backup /path/to/backup/directory --region eu-south-1 --az az1
```

#### Start/Stop/Restart Cluster Services
```bash
lws px cluster-start --region eu-south-1 --az az1
lws px cluster-stop --region eu-south-1 --az az1
lws px cluster-restart --region eu-south-1 --az az1
```

#### Execute Command on Proxmox Host
```bash
lws px exec "free -m" --region eu-south-1 --az az1
```

#### Upload Template to Proxmox
```bash
lws px upload ./ubuntu-20.04-template.tar.gz ubuntu-20.04 --region eu-south-1 --az az1
```

### LXC Container Management

#### Create and Start LXC Container
```bash
lws lxc run --image-id local:vztmpl/ubuntu-20.04-standard_20.04-1_amd64.tar.gz --size medium --count 3 --hostname web-server
```

#### Start/Stop/Reboot Container
```bash
lws lxc start 100 101 102
lws lxc stop 100 101 102
lws lxc reboot 100
```

#### Show Container Details
```bash
lws lxc show 100
```

#### Show All Containers
```bash
lws lxc show
```

#### Scale Container Resources
```bash
lws lxc scale 100 --memory 2048 --cpulimit 2 --storage-size 32G
```

#### Monitor Container Resources
```bash
lws lxc status 100
```

#### Execute Command in Container
```bash
lws lxc exec 100 "apt update && apt upgrade -y"
```

#### Create and Manage Snapshots
```bash
lws lxc snapshot-add 100 snap1
lws lxc snapshots 100
lws lxc snapshot-rm 100 snap1
```

#### Check Network Connectivity
```bash
lws lxc net 100 tcp 80
```

#### Show Container Info and IP
```bash
lws lxc show-info 100
lws lxc show-public-ip 100
```

#### Clone Container
```bash
lws lxc clone 100 101 --full
```

#### Scale Recommendations
```bash
lws lxc scale-check 100
```

#### Manage Container Services
```bash
lws lxc service status nginx 100
lws lxc service restart nginx 100
```

#### Advanced Health Check
```bash
lws lxc health-check 100 --fix
```

#### Resource Monitoring
```bash
lws lxc resources 100 --interval 5 --count 10
```

#### Generate Container Report
```bash
lws lxc report 100 --output json --file container_report.json
```

### Container Backups & Restores

#### Create Container Backup
```bash
lws lxc backup-create 100 --download
```

#### Restore Container from Backup
```bash
lws lxc backup-restore 100 --backup-file backup-100-20230915-123456.tar.gz
```

### Docker Management

#### Install Docker on Container
```bash
lws app setup 100
```

#### Run Docker Container
```bash
lws app run 100 -d -p 80:80 nginx
```

#### Deploy with Docker Compose
```bash
lws app deploy install 100 --compose_file docker-compose.yml --auto_start
```

#### Update Docker Compose Application
```bash
lws app update 100 docker-compose.yml
```

#### View Docker Logs
```bash
lws app logs 100 nginx --follow
```

#### List Docker Containers
```bash
lws app list 100
```

#### Remove Docker
```bash
lws app remove 100 --purge
```

### Security Tools

#### Perform Security Scan
```bash
lws sec scan 100 --scan-type full
```

#### Network Discovery
```bash
lws sec discovery 100
```

### Managing Scaling Thresholds and Triggers

Scaling thresholds and triggers allow **lws** to automatically adjust resources (CPU, memory, storage) for LXC containers based on defined conditions met on both the Proxmox host and the LXC container. This feature ensures optimal performance while preventing resource exhaustion.

#### Example Scaling Configuration
```yaml
scaling:
  host_cpu:
    high_threshold: 0.80
    low_threshold: 0.20
    check_interval_seconds: 60
  
  host_memory:
    high_threshold: 0.85
    low_threshold: 0.30
    check_interval_seconds: 60
  
  lxc_cpu:
    min_threshold: 0.30
    max_threshold: 0.80
    step: 1
    scale_up_multiplier: 1.5
    scale_down_multiplier: 0.5
  
  lxc_memory:
    min_threshold: 0.40
    max_threshold: 0.70
    step_mb: 256
    scale_up_multiplier: 1.25
    scale_down_multiplier: 0.75
  
  limits:
    min_cpu_cores: 1
    max_cpu_cores: 4
    min_memory_mb: 512
    max_memory_mb: 8192
    min_storage_gb: 10
    max_storage_gb: 500
  
  notifications:
    notify_user: true
    dry_run: true
```

> [!TIP]
> Use `notify_user: true` to get immediate feedback on scaling adjustments, which is especially useful in dynamic environments.

> [!WARNING]
> Be cautious when setting the `dry_run` option to `false`, as real scaling adjustments will be applied. Ensure your thresholds and multipliers are well-tested before applying them in production.

## Security Considerations

- **Secure Storage of Credentials**: Consider using environment variables or a secure key store instead of plaintext passwords in configuration files.
- **Restricted Access**: Limit access to the configuration file containing sensitive credentials.
- **Regular Security Scans**: Run `lws sec scan` regularly on your containers to detect security issues.
- **Firewall Rules**: Use the security group functionality to restrict network access to containers.
- **Update Regularly**: Keep your container images and software up to date.

## Best Practices

- **Resource Planning**: Use `lws lxc scale-check` to get recommendations on optimal resource allocation.
- **Regular Backups**: Create regular backups with `lws lxc backup-create` to prevent data loss.
- **Monitoring**: Use `lws lxc resources` to monitor resource usage patterns.
- **Health Checks**: Run `lws lxc health-check` periodically to detect and fix issues.
- **Documentation**: Generate reports with `lws lxc report` for documentation and auditing purposes.

## Contributing

**lws** is an open-source project developed for fun and learning. Contributions are welcome! Feel free to submit issues, feature requests, or pull requests.

### How to Contribute

1. **Fork the Repository**
2. **Create a Branch**
   ```bash
   git checkout -b feature-branch
   ```
3. **Make Changes**
4. **Submit a Pull Request**

> [!TIP]
> Include clear commit messages and documentation with your pull requests to make the review process smoother.

## Roadmap

**lws** continues to evolve. Planned features and improvements include:

- **Multi-Factor Authentication**: Support for MFA in SSH connections.
- **Web Interface**: A simple web dashboard for visual management.
- **Configuration Versioning**: Track changes to container configurations.
- **Integration with CI/CD Pipelines**: Make lws part of your deployment workflows.
- **Kubernetes Support**: Expand management capabilities to Kubernetes clusters.
- **More Security Tools**: Additional security scanning and threat detection tools.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.

## Acknowledgements

- The Proxmox team for their excellent virtualization platform
- The Click developers for the wonderful CLI framework
- All contributors who have helped improve this tool
