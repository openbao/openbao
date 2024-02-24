# Observability Options

## Logging

Consul Template can print verbose debugging output. To set the log level for
Consul Template, use the `-log-level` flag:

```shell
$ consul-template -log-level info ...
```

Or set it via the `CONSUL_TEMPLATE_LOG_LEVEL` environment variable.

```text
<timestamp> [INFO] (cli) received redis from Watcher
<timestamp> [INFO] (cli) invoking Runner
# ...
```

You can also specify the level as debug:

```shell
$ consul-template -log-level debug ...
```

```text
<timestamp> [DEBUG] (cli) creating Runner
<timestamp> [DEBUG] (cli) creating Consul API client
<timestamp> [DEBUG] (cli) creating Watcher
<timestamp> [DEBUG] (cli) looping for data
<timestamp> [DEBUG] (watcher) starting watch
<timestamp> [DEBUG] (watcher) all pollers have started, waiting for finish
<timestamp> [DEBUG] (redis) starting poll
<timestamp> [DEBUG] (service redis) querying Consul with &{...}
<timestamp> [DEBUG] (service redis) Consul returned 2 services
<timestamp> [DEBUG] (redis) writing data to channel
<timestamp> [DEBUG] (redis) starting poll
<timestamp> [INFO] (cli) received redis from Watcher
<timestamp> [INFO] (cli) invoking Runner
<timestamp> [DEBUG] (service redis) querying Consul with &{...}
# ...
```

## Logging to file

Consul Template can log to file as well.
Particularly useful in use cases where it's not trivial to capture *stdout* and/or *stderr*
like for example when Consul Template is deployed as a Windows Service.

These are the relevant CLI flags:

- `-log-file` - writes all the Consul Template log messages
  to a file. This value is used as a prefix for the log file name. The current timestamp
  is appended to the file name. If the value ends in a path separator, `consul-template-`
  will be appended to the value. If the file name is missing an extension, `.log`
  is appended. For example, setting `log-file` to `/var/log/` would result in a log
  file path of `/var/log/consul-template-{timestamp}.log`. `log-file` can be combined with
  `-log-rotate-bytes` and `-log-rotate-duration`
  for a fine-grained log rotation experience.

- `-log-rotate-bytes` - to specify the number of
  bytes that should be written to a log before it needs to be rotated. Unless specified,
  there is no limit to the number of bytes that can be written to a log file.

- `-log-rotate-duration` - to specify the maximum
  duration a log should be written to before it needs to be rotated. Must be a duration
  value such as 30s. Defaults to 24h.

- `-log-rotate-max-files` - to specify the maximum
  number of older log file archives to keep. Defaults to 0 (no files are ever deleted).
  Set to -1 to discard old log files when a new one is created.