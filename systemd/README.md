# Systemd Installation

## Quick Setup

1. Copy the binary to system location:
```bash
sudo cp zdns-rest /usr/local/bin/
sudo chmod +x /usr/local/bin/zdns-rest
```

2. Create config directory and copy config:
```bash
sudo mkdir -p /etc/zdns-rest
sudo cp config/zdns-rest.conf.example /etc/zdns-rest/zdns-rest.conf
sudo chmod 640 /etc/zdns-rest/zdns-rest.conf
```

3. Copy systemd service file:
```bash
sudo cp systemd/zdns-rest.service /etc/systemd/system/
sudo systemctl daemon-reload
```

4. Start and enable the service:
```bash
sudo systemctl start zdns-rest
sudo systemctl enable zdns-rest
```

## Configuration

The service looks for configuration in this order:
1. `--config` flag (if specified)
2. `/etc/zdns-rest/zdns-rest.conf` (key=value format)
3. `~/.zdns.yaml` (YAML format)

Environment variables (format: `ZDNS_<KEY>=<value>`) override config file settings.

## Config File Format

The `.conf` format uses simple `key=value` pairs:

```
bind-port=8080
bind-ip=0.0.0.0
verbosity=4
rate-limit=true
api-key=your-secret-key
```

See `config/zdns-rest.conf.example` for all available options.
