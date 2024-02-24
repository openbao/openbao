## v0.35.0 (November 7, 2023)

NEW FEATURES:
* Add alpha support for Consul namespaces/partitions/peering. [GH-1822](https://github.com/hashicorp/consul-template/pull/1822)

IMPROVEMENTS:
* Bump golang.org/x/text from 0.13.0 to 0.14.0. [GH-1830](https://github.com/hashicorp/consul-template/pull/1830)
* Bump golang.org/x/sys from 0.13.0 to 0.14.0. [GH-1829](https://github.com/hashicorp/consul-template/pull/1829)
* Bump github.com/hashicorp/consul/sdk from 0.14.1 to 0.15.0. [GH-1826](https://github.com/hashicorp/consul-template/pull/1826)
* Bump github.com/hashicorp/consul/api from 1.25.1 to 1.26.1. [GH-1827](https://github.com/hashicorp/consul-template/pull/1827)

## v0.34.0 (October 11, 2023)

IMPROVEMENTS:
* Refactor deprecated Vault calls. [GH-1768](https://github.com/hashicorp/consul-template/pull/1768)
* Remove explicit math/rand seed. [GH-1793](https://github.com/hashicorp/consul-template/pull/1793)
* Bump github.com/hashicorp/vault/api/auth/kubernetes from 0.4.1 to 0.5.0. [GH-1805](https://github.com/hashicorp/consul-template/pull/1805)
* Bump go version from 1.20 to 1.21. [GH-1819](https://github.com/hashicorp/consul-template/pull/1819)
* Bump golang.org/x/text from 0.11.0 to 0.13.0. [GH-1802](https://github.com/hashicorp/consul-template/pull/1802)
* Bump golang.org/x/sys from 0.11.0 to 0.13.0. [GH-1816](https://github.com/hashicorp/consul-template/pull/1816)
* Bump github.com/hashicorp/consul/api from 1.23.0 to 1.25.1. [GH-1787](https://github.com/hashicorp/consul-template/pull/1787) [GH-1815](https://github.com/hashicorp/consul-template/pull/1815)
* Bump github.com/hashicorp/vault/api from 1.9.2 to 1.10.0. [GH-1806](https://github.com/hashicorp/consul-template/pull/1806)
* Bump golangci/golangci-lint-action from 3.6.0 to 3.7.0. [GH-1812](https://github.com/hashicorp/consul-template/pull/1812)
* add golangci-lint. [GH-1773](https://github.com/hashicorp/consul-template/pull/1773) [GH-1774](https://github.com/hashicorp/consul-template/pull/1774/files)

## v0.33.0 (August 9, 2023)

IMPROVEMENTS:
* Add support for setting Vault CA from VAULT_CACERT_BYTES. [GH-1782](https://github.com/hashicorp/consul-template/pull/1782)
* Add CLI support for exec env configs. [GH-1761](https://github.com/hashicorp/consul-template/pull/1761)
* Add function for HMAC SHA256. [GH-1760](https://github.com/hashicorp/consul-template/pull/1760)
* Bump go version from 1.19 to 1.20. [GH-1783](https://github.com/hashicorp/consul-template/pull/1783)
* Bump hashicorp/consul/api from 1.13.0 to 1.23.0. [GH-1781](https://github.com/hashicorp/consul-template/pull/1781) & [GH-1758](https://github.com/hashicorp/consul-template/pull/1758)
* Bump BurntSushi/toml from 1.2.1 to 1.3.2. [GH-1766](https://github.com/hashicorp/consul-template/pull/1766)
* Bump golang.org/x/sys from 0.10.0 to 0.11.0. [GH-1788](https://github.com/hashicorp/consul-template/pull/1788)
* Bump golang.org/x/net from 0.12.0 to 0.13.0. [GH-1784](https://github.com/hashicorp/consul-template/pull/1784)
* Bump golang.org/x/text from 0.7.0 to 0.10.0. [GH-1763](https://github.com/hashicorp/consul-template/pull/1763)
* Bump stretchr/testify from 1.8.2 to 1.8.4. [GH-1757](https://github.com/hashicorp/consul-template/pull/1757)
* Bump hashicorp/vault/api/auth/kubernetes from 0.3.0 to 0.4.1. [GH-1755](https://github.com/hashicorp/consul-template/pull/1755)

REPO MAINTENANCE:
* Code quality fixes and various lint improvements. [GH-1762](https://github.com/hashicorp/consul-template/pull/1762)


## v0.32.0 (May 18, 2023)

IMPROVEMENTS:
* Add support for Vault agent environment variables. [GH-1741](https://github.com/hashicorp/consul-template/pull/1741)
* Upgrade hashicorp/vault/api from 1.8.2 to 1.9.1. [GH-1743](https://github.com/hashicorp/consul-template/pull/1743)

REPO MAINTENANCE:
* remove repo-specific codeql action, in favor of centralized job. [GH-1740](https://github.com/hashicorp/consul-template/pull/1740/files)


## v0.31.0 (Apr 06, 2023)

IMPROVEMENTS:

* Added `ExtFuncMap` to allow external functions to be passed to the template. This gives users ability to add functions to the library and selective opaque existing ones. [1708](https://github.com/hashicorp/consul-template/pull/1708)
* Vault: add new configuration option `vault-client-user-agent`, when set consul-template will use the set `User-Agent` when making requests to vault. This change is being made as part of a broader effort for Vault Agent to send its version as part of a User-Agent string in requests to Vault. Agent will then consume the latest version of consul-template, then use this new config to set the correct `User-Agent`. [GH-1725](https://github.com/hashicorp/consul-template/pull/1725)
* Upgrade golang.org/x/net from 0.4.0 to 0.7.0. [GH-1711](https://github.com/hashicorp/consul-template/pull/1711)
* Upgrade Sprig from v2 to v3. [GH-1699](https://github.com/hashicorp/consul-template/pull/1699/files)
* Upgrage github.com/stretchr/testify from 1.8.1 to 1.8.2 [1726](https://github.com/hashicorp/consul-template/pull/1726)
* Add copyright headers to file for compliance. [GH-1721](https://github.com/hashicorp/consul-template/pull/1721)
* Improve use of inclusive language [GH-1731](https://github.com/hashicorp/consul-template/pull/1731)

## v0.30.0 (Jan 09, 2023)

IMPROVEMENTS:
* option to exit with an error upon failure to look up data (instead of blocking and waiting for it). [[GH-1695](https://github.com/hashicorp/consul-template/pull/1695), [GH-1637](https://github.com/hashicorp/consul-template/issues/1637)]
* tweak defaults for performance improvements [[GH-1697](https://github.com/hashicorp/consul-template/pull/1697), [GH-1603](https://github.com/hashicorp/consul-template/issues/1603)]

BUG FIXES:
* properly respect reload/kill configured signals [[GH-1690](https://github.com/hashicorp/consul-template/pull/1690), [GH-1671](https://github.com/hashicorp/consul-template/issues/1671)]
* Fix 'toTitle' function for a better support for word boundaries and unicode punctuation [[GH-1678](https://github.com/hashicorp/consul-template/pull/1678)]

## v0.29.6 (Nov 30, 2022)

BUG FIXES:
* Force kill fails to kill the process group in exec mode [[GH-1666](https://github.com/hashicorp/consul-template/issues/1666), [GH-1668](https://github.com/hashicorp/consul-template/pull/1668)]
* Fix user set in dockerfile [[GH-1662](https://github.com/hashicorp/consul-template/pull/1662)]
* Module version update to x/text package for CVE-2022-32149, though the CVE didn't impact consul-template [[GH-1655](https://github.com/hashicorp/consul-template/issues/1655)]

IMPROVEMENTS:
* Update build to use 1.18+ to add template support for continue and break [[GH-1663](https://github.com/hashicorp/consul-template/issues/1663)]
* Template function 'splitToMap' [[GH-1664](https://github.com/hashicorp/consul-template/pull/1664)]
* Template function 'mustEnv' [[GH-1657](https://github.com/hashicorp/consul-template/pull/1657)]

## v0.29.5 (Oct 04, 2022)

BUG FIXES:
* Fix issue with ownership change detection incorrectly indicating a change when a user or group was set but not both [[GH-1652](https://github.com/hashicorp/consul-template/pull/1652)]
* Fix issue with nomad configuration setup [[GH-1653](https://github.com/hashicorp/consul-template/pull/1653)]

## v0.29.4 (Sept 30, 2022)

BUG FIXES:
* Fix goroutine leak in vault token watcher on config reload. [[GH-1650](https://github.com/hashicorp/consul-template/issues/1650)]

## v0.29.3 (Sept 30, 2022)

IMPROVEMENTS:
* Vault token management refactor to increase encapsulation and enable testing. [[GH-1645](https://github.com/hashicorp/consul-template/pull/1645)]

BUG FIXES:
* Log child process successful exits at INFO level (not ERR). [[GH-1649](https://github.com/hashicorp/consul-template/pull/1649), [GH-1282](https://github.com/hashicorp/consul-template/issues/1282)]
* Fix reading vault agent token in wrapped format [[GH-1498](https://github.com/hashicorp/consul-template/issues/1498)]
* Fix issue with transient goroutine leak causing unnecessary memory growth. [[GH-1644](https://github.com/hashicorp/consul-template/pull/1644)]
* Fix issue with pkiCerts failing if cert file is moved. [[GH-1639](https://github.com/hashicorp/consul-template/pull/1639)]


## v0.29.2 (Aug 16, 2022)

IMPROVEMENTS:
* Nomad services support use of `byTab` template function. [[GH-1594](https://github.com/hashicorp/consul-template/pull/1594)]

BUG FIXES:
* Fix issue with pkiCert caching certificate based on consul key path. [[GH-1611](https://github.com/hashicorp/consul-template/pull/1611), [GH-1607](https://github.com/hashicorp/consul-template/issues/1607)]
* Fix issue with setting the reload_signal to an empty string ("") not disabling the reload_signal as documented. [[GH-1610](https://github.com/hashicorp/consul-template/pull/1610), [GH-1428](https://github.com/hashicorp/consul-template/issues/1428), [GH-1442](https://github.com/hashicorp/consul-template/issues/1442)]
* Limit Setgpid setting to strictly `sh -c` wrapped calls. [[GH-1600](https://github.com/hashicorp/consul-template/pull/1600), [GH-1604](https://github.com/hashicorp/consul-template/issues/1604)]
* Fix potential for nil pointer dereference in vault config debug output. [[GH-1586](https://github.com/hashicorp/consul-template/issues/1586)]

SECURITY:
* Filter Vault Secrets from text/template error messages, [CVE-2022-38149](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-38149). [[GH-1613](https://github.com/hashicorp/consul-template/pull/1613)]
* Updates dependencies several of which had known CVEs. [[GH-1622](https://github.com/hashicorp/consul-template/pull/1622), [GH-1614](https://github.com/hashicorp/consul-template/issues/1614)]


## v0.29.1 (Jun 24, 2022)

IMPROVEMENTS:

* Kubernetets Vault authentication support [[GH-1580](https://github.com/hashicorp/consul-template/pull/1580)]
* Nomad: add support for querying consistent subset of services [[GH-1579](https://github.com/hashicorp/consul-template/pull/1579)]

BUG FIXES:

* pkiCert now useful, getting the certificate, private key and CA [[GH-1591](https://github.com/hashicorp/consul-template/pull/1591), [1567](https://github.com/hashicorp/consul-template/issues/1567)]
* fix issue with VaultConfig debug printing [[GH-1587](https://github.com/hashicorp/consul-template/pull/1587)]
* update crypto package version [[GH-1592](https://github.com/hashicorp/consul-template/pull/1592), [GH-1582](https://github.com/hashicorp/consul-template/issues/1582)]
* fix sort.Stable sorting [[GH-1578](https://github.com/hashicorp/consul-template/pull/1578)]


## v0.29.0 (Apr 20, 2022)

IMPROVEMENTS:
* Nomad Service Discovery! [[GH-1565](https://github.com/hashicorp/consul-template/pull/1565)]
* New `pkiCert` template function provides self-caching certificates [[GH-1559](https://github.com/hashicorp/consul-template/pull/1559), [GH-1259](https://github.com/hashicorp/consul-template/issues/1259)]
* Add string trim template functions [[GH-1558](https://github.com/hashicorp/consul-template/pull/1558), [GH-1544](https://github.com/hashicorp/consul-template/issues/1544)]

BUG FIXES:
* Fix issue with multiple identical templates using the same path [[GH-1573](https://github.com/hashicorp/consul-template/pull/1573)]
* Reduce signal processing overhead [[GH-1575](https://github.com/hashicorp/consul-template/pull/1575), [GH-1548](https://github.com/hashicorp/consul-template/issues/1548)]
* Fix issue with template user/group setting [[GH-1571](https://github.com/hashicorp/consul-template/pull/1571), [GH-1570](https://github.com/hashicorp/consul-template/issues/1570)]


## v0.28.1 (Apr 04, 2022)

IMPROVEMENTS:
* Allow setting template destination file ownership by name (with uid/gid compatibilty) [[GH-1541](https://github.com/hashicorp/consul-template/pull/1541), [GH-1551](https://github.com/hashicorp/consul-template/pull/1551)]
* better writeToFile user/group ownership behaviors [[GH-1549](https://github.com/hashicorp/consul-template/pull/1549)]
* configurable lease check wait for non-renewable secrets [[GH-1546](https://github.com/hashicorp/consul-template/pull/1546)]

## v0.28.0 (Mar 04, 2022)

BUG FIXES:
* Fix issue returning typed nil pointers in template functions [[GH-1535](https://github.com/hashicorp/consul-template/pull/1535), [GH-1418](https://github.com/hashicorp/consul-template/issues/1418)]
* Support secret write queries w/ an empty write [[GH-1532](https://github.com/hashicorp/consul-template/pull/1532), [GH-1453](https://github.com/hashicorp/consul-template/issues/1453)]


IMPROVEMENTS:
* Add sprig library [[GH-1312](https://github.com/hashicorp/consul-template/pull/1312)]
* Add option to make template errors non-fatal [[GH-1420](https://github.com/hashicorp/consul-template/pull/1420), [GH-1419](https://github.com/hashicorp/consul-template/issues/1419), [GH-1289](https://github.com/hashicorp/consul-template/issues/1289)]
* Support for accepting a custom logger for a child process [[GH-1515](https://github.com/hashicorp/consul-template/pull/1515)]
* Add support for providing Consul ACL Token via a file [[GH-1516](https://github.com/hashicorp/consul-template/pull/1516), [GH-1429](https://github.com/hashicorp/consul-template/issues/1429)]
* Allow setting user/group ownership of template output [[GH-1531](https://github.com/hashicorp/consul-template/pull/1531), [GH-1497](https://github.com/hashicorp/consul-template/issues/1497), [GH-639](https://github.com/hashicorp/consul-template/issues/639)]
* Logging to file [[GH-1534](https://github.com/hashicorp/consul-template/pull/1534), [GH-1416](https://github.com/hashicorp/consul-template/issues/1416)]]
* Support command/exec lists [[GH-1543](https://github.com/hashicorp/consul-template/pull/1543), [GH-1518](https://github.com/hashicorp/consul-template/issues/1518)]


## v0.27.2 (Nov 05, 2021)

BUG FIXES:
* Syslog doesn't work after upgrade to 0.27 [[GH-1523](https://github.com/hashicorp/consul-template/issues/1523), [GH-1529](https://github.com/hashicorp/consul-template/pull/1529)]

## v0.27.1 (Sep 22, 2021)

IMPROVEMENTS:
* Updated command execution on \*nix systems to call the command directly,
  without the `sh -c` wrapping shell command, *only* in cases where the command
  is a single word (no spaces). This allows docker to run in environments (like
  a minimal docker image) where there is no shell (`sh`). Multi-word commands
  will continue to use the wrapping shell call.
  [[GH-1509](https://github.com/hashicorp/consul-template/pull/1509),
  [GH-1508](https://github.com/hashicorp/consul-template/issues/1508)]

SECURITY:
* Updated golang.or/x/crypto dependency for CVE-2020-29652. [[GH-1507](https://github.com/hashicorp/consul-template/issues/1507)]


## v0.27.0 (Aug 16, 2021)

BREAKING CHANGES:
* All command execution calls are now made (on \*nix systems) using a shell command call ('/bin/sh -c ...') with [process group](https://man7.org/linux/man-pages/man2/setpgid.2.html) set to ensure all signals are propagated to the called commands. This was done to eliminate the need for parsing the shell command as it was a continual source of bugs. Windows systems currently only support single command calls because of no (known) 'sh -c' equivalent on Windows. [[GH-1496](https://github.com/hashicorp/consul-template/pull/1496), [GH-1494](https://github.com/hashicorp/consul-template/pull/1494)]

IMPROVEMENTS:
* New Docker Image. Similar to old Alpine image but modernized and simplified [[GH-1481](https://github.com/hashicorp/consul-template/issues/1481), [GH-1484](https://github.com/hashicorp/consul-template/pull/1484)]
* New, more obvious, log level environment variable [[GH-1383](https://github.com/hashicorp/consul-template/pull/1383)]
* New 'writeToFile' template function [[GH-1495](https://github.com/hashicorp/consul-template/pull/1495), [GH-1077](https://github.com/hashicorp/consul-template/issues/1077)]
* New mergeMap and mergeMapWithOverride template functions [[GH-1500](https://github.com/hashicorp/consul-template/pull/1500), [GH-1499](https://github.com/hashicorp/consul-template/issues/1499)].

BUG FIXES:
* Ignore SIGURG signals by default [[GH-1486](https://github.com/hashicorp/consul-template/issues/1486), [GH-1487](https://github.com/hashicorp/consul-template/pull/1487)]
* Fix issue with command argument parsing when using sub-shell calls [[GH-1482](https://github.com/hashicorp/consul-template/issues/1482)]

## v0.26.0 (Jun 10, 2021)

BREAKING CHANGES:
* Docker: We have moved to a new Docker image build pipeline that is creating a simplified image containing only the executable, meant primarily to be used as a base image. If you would like the previous, more complex image back please file an issue. Thanks.

IMPROVEMENTS:
* Arm CPUs no longer need special builds [[GH-1471](https://github.com/hashicorp/consul-template/pull/1471), [GH-1404](https://github.com/hashicorp/consul-template/issues/1404)]
* add 'md5sum' template function [[GH-1464](https://github.com/hashicorp/consul-template/pull/1464)]
* add 'envOrDefault' template function [[GH-1461](https://github.com/hashicorp/consul-template/pull/1461), [GH-829](https://github.com/hashicorp/consul-template/issues/829)]
* configurable Vault default lease duration [[GH-1446](https://github.com/hashicorp/consul-template/pull/1446), [GH-1445](https://github.com/hashicorp/consul-template/issues/1445)]
* unescaped JSON template filter functions [[GH-1432](https://github.com/hashicorp/consul-template/pull/1432), [GH-1430](https://github.com/hashicorp/consul-template/issues/1430)]
* go spew debugging template functions [[GH-1406](https://github.com/hashicorp/consul-template/pull/1406)]
* add service tagged addresses to health service data [[GH-1400](https://github.com/hashicorp/consul-template/pull/1400), [GH-1398](https://github.com/hashicorp/consul-template/issues/1398)]
* allow running via Windows Service Control [[GH-1382](https://github.com/hashicorp/consul-template/pull/1382)]

BUG FIXES:
* fix command shell quoting issue [[GH-1477](https://github.com/hashicorp/consul-template/pull/1477), [GH-1456](https://github.com/hashicorp/consul-template/issues/1456), [GH-1463](https://github.com/hashicorp/consul-template/issues/1463)]
* rework logging, add tests and fix missing timestamp issue [[GH-1476](https://github.com/hashicorp/consul-template/pull/1476), [GH-1475](https://github.com/hashicorp/consul-template/issues/1475)]
* fix issue with connect/health services using same cache entry [[GH-1474](https://github.com/hashicorp/consul-template/pull/1474), [GH-1458](https://github.com/hashicorp/consul-template/issues/1458)]
* fix issue with ownership when perms option is set [[GH-1473](https://github.com/hashicorp/consul-template/pull/1473), [GH-1379](https://github.com/hashicorp/consul-template/issues/1379)]
* fixes issue with 'secrets' and Vault kv-v2 [[GH-1468](https://github.com/hashicorp/consul-template/pull/1468), [GH-1274](https://github.com/hashicorp/consul-template/issues/1274), [GH-1275](https://github.com/hashicorp/consul-template/issues/1275),  [GH-1462](https://github.com/hashicorp/consul-template/issues/1462)]


## v0.25.2 (Feb 19, 2021)

BREAKING CHANGES:
* version output from -v/-version should go to STDOUT (not STDERR)[[GH-1452](https://github.com/hashicorp/consul-template/issues/1452), [GH-1455](https://github.com/hashicorp/consul-template/pull/1455)]
* log date output format consistency fix [[GH-1412](https://github.com/hashicorp/consul-template/pull/1412)]

BUG FIXES:
* fix extra logging/broken log levels [[GH-1438](https://github.com/hashicorp/consul-template/issues/1438), [GH-1426](https://github.com/hashicorp/consul-template/issues/1426), [GH-1454](https://github.com/hashicorp/consul-template/pull/1454), []()]
* fix issue with vault secret panic/missing nil check [[GH-1450](https://github.com/hashicorp/consul-template/issues/1450), [GH-1447](https://github.com/hashicorp/consul-template/pull/1447)]
* Override block_query_wait doesn't work [[GH-1441](https://github.com/hashicorp/consul-template/issues/1441), [GH-1443](https://github.com/hashicorp/consul-template/pull/1443)]

IMPROVEMENTS:
* vault secret ttl handling [[Gh-1451](https://github.com/hashicorp/consul-template/pull/1451)]

## v0.25.1 (Jul 27, 2020)

IMPROVEMENTS:
* Update whitelist/blacklist config options to allowlist/denylist with backward compatibility [[GH-1388](https://github.com/hashicorp/consul-template/pull/1388)]

BUG FIXES:
* Fix issue rendering empty file to disk [[GH-1393](https://github.com/hashicorp/consul-template/issues/1393)][[GH-1397](https://github.com/hashicorp/consul-template/pull/1397)]
* Fix issue with Vault PKI cert expiration [[GH-1394](https://github.com/hashicorp/consul-template/pull/1394)]
* Fix issue reading Vault KVv2 secrets metadata [[GH-1396](https://github.com/hashicorp/consul-template/issues/1396)][[GH-1399](https://github.com/hashicorp/consul-template/pull/1399)]

## v0.25.0 (Apr 27, 2020)

IMPROVEMENTS:

* Add minimum and maximum math functions [[GH-1323](https://github.com/hashicorp/consul-template/pull/1323)]

* Allow overriding the default delimiter [[GH-1290](https://github.com/hashicorp/consul-template/pull/1290)]

* Add weights field for HealthService [[GH-1288](https://github.com/hashicorp/consul-template/pull/1288)]

* Beta support for Consul Namespaces (Consul Enterprise feature) [[GH-1320](https://github.com/hashicorp/consul-template/pull/1320), [GH-1303](https://github.com/hashicorp/consul-template/issues/1303)]

* Added sha256Hex function [[GH-1327](https://github.com/hashicorp/consul-template/pull/1327)]

* Make timeout for blocking query configurable [[GH-1329](https://github.com/hashicorp/consul-template/pull/1329)]

* docker: alpine without docker-base [[GH-1333](https://github.com/hashicorp/consul-template/pull/1333)]

* Add parseYAML helper [[GH-1344](https://github.com/hashicorp/consul-template/pull/1344)]

* Add lease calculation for rotating secrets [[GH-1358](https://github.com/hashicorp/consul-template/pull/1358)]

* Allow to set application name in syslog [[GH-1367](https://github.com/hashicorp/consul-template/pull/1367)]


BUG FIXES:

* Don't renew vault token when no token is set [[GH-1352](https://github.com/hashicorp/consul-template/pull/1352), [GH-1297](https://github.com/hashicorp/consul-template/issues/1297)]

* Fix bug looking up versioned vault secrets [[GH-1354](https://github.com/hashicorp/consul-template/pull/1354), [GH-1350](https://github.com/hashicorp/consul-template/issues/1350)]

* Fix issue reading kv2 vault secrets for key paths starting with "data" [[GH-1341](https://github.com/hashicorp/consul-template/pull/1341), [GH-1340](https://github.com/hashicorp/consul-template/issues/1340)]

* Fix data race in child.go [[GH-1373](https://github.com/hashicorp/consul-template/pull/1373), [GH-1372](https://github.com/hashicorp/consul-template/issues/1372)]

* Fix issue with template commands when used as library [[GH-1370](https://github.com/hashicorp/consul-template/pull/1370), [GH-1369](https://github.com/hashicorp/consul-template/issues/1369)]

DOCUMENTATION:

* How to run multiple things in template commands [[GH-1375](https://github.com/hashicorp/consul-template/pull/1375)]

* Template command_timeout clarifications [[GH-1370](https://github.com/hashicorp/consul-template/pull/1370), [GH-1369](https://github.com/hashicorp/consul-template/issues/1369)]

* ByMeta does not accept `services` as input [[GH-1348](https://github.com/hashicorp/consul-template/issues/1348)]


## v0.24.1 (Jan 24, 2020)

BUG FIXES:

* Make user non-numeric to satisfy PSP [[GH-1332](https://github.com/hashicorp/consul-template/pull/1332)]
* fatal error: PowerRegisterSuspendResumeNotification failure on windows [[GH-1335](https://github.com/hashicorp/consul-template/issues/1335)]

## v0.24.0 (Jan 08, 2020)

BREAKING CHANGES:

* Alpine Docker image no longer runs as root and so doesn't change ownership of the /consul-template/data and /consul-template/config directories to the consul-template user. See the [Docker Image Use](https://github.com/hashicorp/consul-template#docker-image-use) topic in the documentation for more.

BUG FIXES:

* arm builds are linked against wrong library [[GH-1317](https://github.com/hashicorp/consul-template/issues/1317), [GH-1326](https://github.com/hashicorp/consul-template/pull/1326)]
* consul-template container runs as root - breaks CISO compliance [[GH-1321](https://github.com/hashicorp/consul-template/issues/1321), [GH-1324](https://github.com/hashicorp/consul-template/pull/1324)]
* 'sockaddr' function returning whitespace after address [[GH-1314](https://github.com/hashicorp/consul-template/issues/1314), [GH-1315](https://github.com/hashicorp/consul-template/pull/1315)]
* runTemplate - DEBUG logging is needed to identify missing dependencies [[GH-1308](https://github.com/hashicorp/consul-template/issues/1308), [GH-1309](https://github.com/hashicorp/consul-template/pull/1309)]
* Remove code/logic for working with (long deprecated) Vault grace [[GH-1284](https://github.com/hashicorp/consul-template/pull/1284)]

## v0.23.0 (Nov 13, 2019)

IMPROVEMENTS:

* Support Configuring Consul Connect Clients [[GH-1262](https://github.com/hashicorp/consul-template/issues/1262), [GH-1304](https://github.com/hashicorp/consul-template/pull/1304), [GH-1306](https://github.com/hashicorp/consul-template/pull/1306)]

## v0.22.1 (Nov 08, 2019)

SECURITY:

* curl is vulnerable in the latest alpine docker image [[GH-1302](https://github.com/hashicorp/consul-template/issues/1302)]

BUG FIXES:

* fix breaking change for loop [[GH-1285](https://github.com/hashicorp/consul-template/issues/1285)]

## v0.22.0 (September 10, 2019)

IMPROVEMENTS:

* Add rate limiting to consul api calls [[GH-1279](https://github.com/hashicorp/consul-template/pull/1279)]
* Add `byMeta` function [[GH-1237](https://github.com/hashicorp/consul-template/pull/1237)]
* Add support for : and = in service tag values [[GH-1149](https://github.com/hashicorp/consul-template/pull/1149), [GH-1049](https://github.com/hashicorp/consul-template/issues/1049)]
* Add `explodeMap` function [[GH-1148](https://github.com/hashicorp/consul-template/pull/1148)]
* Don't wait for splay when stopping child runner [[GH-1141](https://github.com/hashicorp/consul-template/pull/1141)]
* Add `safels` and `safetree` functions [[GH-1132](https://github.com/hashicorp/consul-template/pull/1132)]
* Support Vault certificates with no lease [[GH-1106](https://github.com/hashicorp/consul-template/pull/1106)]
* Add wrapper function for go-sockaddr templating [[GH-1087](https://github.com/hashicorp/consul-template/pull/1087)]
* Build binaries for arm64 platform [[GH-1251](https://github.com/hashicorp/consul-template/pull/1251)]

BUG FIXES:

* Fix arm/arm64 builds by enabling CGO and restricting builds to Linux [workaround for [go/issues/32912](https://github.com/golang/go/issues/32912)]

## v0.21.3 (September 05, 2019)

BUG FIXES:

* Fix regression in non-renewable sleep [[GH-1277](https://github.com/hashicorp/consul-template/pull/1277), [GH-1272](https://github.com/hashicorp/consul-template/issues/1272), [GH-1276](https://github.com/hashicorp/consul-template/issues/1276)]

## v0.21.2 (August 31, 2019)

BUG FIXES:

* Fix regression in backup [[GH-1271](https://github.com/hashicorp/consul-template/pull/1271), [GH-1270](https://github.com/hashicorp/consul-template/issues/1270)]

## v0.21.1 (August 30, 2019)

BUG FIXES:

* Fixed issue in Vault call retry logic [[GH-1269](https://github.com/hashicorp/consul-template/pull/1269), [GH-1224](https://github.com/hashicorp/consul-template/issues/1224)]
* Fixed race in backup [[GH-1265](https://github.com/hashicorp/consul-template/pull/1265), [GH-1264](https://github.com/hashicorp/consul-template/issues/1264)]
* Fixed issue when reading deleted secret [[GH-1260](https://github.com/hashicorp/consul-template/pull/1260), [GH-1198](https://github.com/hashicorp/consul-template/issues/1198)]
* Fix issue with Vault writes [[GH-1257](https://github.com/hashicorp/consul-template/pull/1257), [GH-1252](https://github.com/hashicorp/consul-template/issues/1252)]
* Fix loop to work with template set integers [[GH-1255](https://github.com/hashicorp/consul-template/pull/1255), [GH-1143](https://github.com/hashicorp/consul-template/issues/1143)]

## v0.21.0 (August 05, 2019)

IMPROVEMENTS:

* Migrated to use Go modules [[GH-1244](https://github.com/hashicorp/consul-template/pull/1244), [GH-1173](https://github.com/hashicorp/consul-template/issues/1173), [GH-1208](https://github.com/hashicorp/consul-template/pull/1208)[GH-1232](https://github.com/hashicorp/consul-template/pull/1232)]
* Template blacklist feature [[GH-1243](https://github.com/hashicorp/consul-template/pull/1243)]

## v0.20.1 (July 30, 2019)

BUG FIXES:

* Fixed issue with exec running before template rendering when wait is set [[GH-1229](https://github.com/hashicorp/consul-template/issues/1229), [GH-1209](https://github.com/hashicorp/consul-template/issues/1209)]
* Fixed issue with templates not rendering with `-once` [[GH-1227](https://github.com/hashicorp/consul-template/pull/1227), [GH-1196](https://github.com/hashicorp/consul-template/issues/1196), [GH-1207](https://github.com/hashicorp/consul-template/issues/1207)]
* Fixed regression with ~/.vault-token and with vault_agent_token_file not respecting renew_token [[GH-1228](https://github.com/hashicorp/consul-template/issues/1228), [GH-1189](https://github.com/hashicorp/consul-template/issues/1189)]
* CA certificates missing from docker 'light' image [[GH-1200](https://github.com/hashicorp/consul-template/issues/1200)]
* Fixed issue with dedup data garbage in Consul KV [[GH-1158](https://github.com/hashicorp/consul-template/issues/1158), [GH-1168](https://github.com/hashicorp/consul-template/issues/1168)]
* Fixed bad case in import path [[GH-1139](https://github.com/hashicorp/consul-template/issues/1139)]
* Documented limits on using "." in service names [[GH-1205](https://github.com/hashicorp/consul-template/issues/1205)]

## v0.20.0 (February 19, 2019)

IMPROVEMENTS:

* Support for Consul service metadata [GH-1113]
* Support for Vault's KV v2 secrets engine, including versioned secrets [GH-1180].
* Support for Vault Enterprise's namespaces feature [GH-1181].
* Support for a new config parameter, `vault_agent_token_file`, which supports loading the Vault token from the contents of a dynamically updated file. This is intended for use in environments like Kubernetes [GH-1185].
* A template's destination file will now have its user and group permissions preserved on supported OSes (Linux/MacOS) [GH-1061].

BUG FIXES:

* The indent function no longer panics on negative spaces variable [GH-1127]
* Fixed an issue that caused `exec` to not be called with multiple templates and `wait` configured [GH-1043]
* Fixed an issue where Consul Template did not wait for most of a non-renewable secret's lease before attempting to refresh the secret. [GH-1183]
 
## v0.19.5 (June 12, 2018)

BUG FIXES:

  * The de-duplication feature was incorrectly calculating the hash of dependency 
    values over an unstable encoding of the data. This meant that in most cases 
    the templates were being re-written to KV and on all watching template 
    instances every minimum update time (i.e. `wait { min = X }`). At best this
    was a lot of wasted work, in some cases it caused 100% CPU usage when template 
    instance leadership was split. [GH-1099, GH-1095]
  * Fixed an issue where we waited unnecessarily for a child process to exit [GH-1101]

IMPROVEMENTS:

  * Initiating runner log level moved to DEBUG [GH-1088]


## v0.19.4 (October 30, 2017)

BREAKING CHANGES:

  * The version of Consul Template is now taken into account when using
    de-duplication mode. Without bundling the version, it's challenging to
    upgrade existing clusters or run multiple versions of Consul Template on the
    same cluster and template simultaneously. [GH-1025]

BUG FIXES:

  * Remove references to unsupported `dump_signal` configuration

  * Update vendor libraries to support Consul 1.0.0 changes for better test
    stability

  * Renew unwrapped Vault token (previously Consul Template) would try to renew
    the wrapped token, which would not work.

  * Do not sort results when `~near` queries are used [GH-1027]

  * Handle integer overflow in exponential backoff calculations
    [GH-1031, GH-1028]

  * Properly preserve existing file permissions [GH-1037]

IMPROVEMENTS:

  * Compile with Go 1.9.2

  * The Vault grace period in the config is now set to 15 seconds as the
    default. This matches Vault's default configuration for consistency.

  * Add `indent` function for indenting blocks of text in templates

  * Allow additional colons in the template command on the CLI [GH-1026]

  * Add Vault Transit example for key exfiltration [GH-1014]

  * Add a new option for disabling recursive directory creation per template
    [GH-1033]

  * Allow dots in node names [GH-977]

## v0.19.3 (September 11, 2017)

BUG FIXES:

  * Fix a bug that would cause once mode to not exit when the file pre-existed
    on disk with the correct contents. [GH-1000]

## v0.19.2 (September 1, 2017)

BUG FIXES:

  * Fix a critical bug that would cause a hot loop for some TTL durations.
      [GH-1004]

## v0.19.1 (August 25, 2017)

IMPROVEMENTS:

  * The runner's render event now includes the last-rendered template contents.
      This is useful when embedding Consul Template as a library. [GH-974-975]

  * Use the new Golang API renewer [GH-978]

  * Compile and build with Go 1.9

BUG FIXES:

  * Add per-template option `error_on_missing_key`. This causes the template to
      error when the user attempts to access a key in a map or field in a struct
      that does not exist. Previous behavior was to print `<no value>`, which
      might not be the desired behavior. This is opt-in behavior on a
      per-template basis. There is no global option. A future version of
      Consul Template will switch the default behavior to this safer format, but
      that change will be clearly called out as a breaking change in the future.
      Users should set `error_on_missing_key = false` in their configuration
      files if they are relying on the current `<no value>` behavior.
      [GH-973, GH-972]
  * Ensure all templates are rendered before spawning commands [GH-991, GH-995]

## v0.19.0 (June 29, 2017)

BREAKING CHANGES:

  * All previous deprecation errors have been removed and associated configs or
      CLI options are no longer valid. It is highly recommended that you run
      v0.18.5 and resolve any deprecations before upgrading to this version!

IMPROVEMENTS:

  * Add new configuration option `vault.grace`, which configures the grace
      period between lease renewal and secret re-acquisition. When renewing a
      secret, if the remaining lease is less than or equal to the configured
      grace, Consul Template will request a new credential. This prevents Vault
      from revoking the credential at expiration and Consul Template having a
      stale credential. **If you set this to a value that is higher than your
      default TTL or max TTL, Consul Template will always read a new secret!**
  * Add a new option to `datacenters` to optionally ignore inaccessible
      datacenters [GH-908].

BUG FIXES:

  * Use the logger as soon as its available for output [GH-947]
  * Update Consul API library to fix a bug where custom CA configuration was
      ignored [GH-965]


## v0.18.5 (May 25, 2017)

BREAKING CHANGES:

  * Retry now has a maximum default. Previous versions of Consul Template
      would retry indefinitely, potentially allowing the time between retries to
      reach days, months, or years due to the exponential nature. Users wishing
      to use the old behavior should set `max_backoff = 0` in their
      configurations. [GH-940]

IMPROVEMENTS:

  * Add support for `MaxBackoff` in Retry options [GH-938, GH-939]
  * Compile with Go 1.8.3

## v0.18.4 (May 25, 2017)

BUG FIXES:

  * Compile with go 1.8.2 for the security fix. The code is exactly the same as
      v0.18.3.

## v0.18.3 (May 9, 2017)

IMPROVEMENTS:

  * Add support for local datacenter in node queries [GH-862, GH-927]
  * Add support for service tags on health checks [Consul vendor update]

BUG FIXES:

  * Seed the random generator for splay values  
  * Reset retries counter on successful contact [GH-931]
  * Return a nil slice instead of an error for non-existent maps
      [GH-906, GH-932]
  * Do not return data in dedup mode if the template is unchanged
      [GH-933 GH-698]

NOTABLE:

  * Consul Template is now built with Go 1.8.1
  * Update internal library to Consul 0.8.2 - this should not affect any users

## v0.18.2 (March 28, 2017)

IMPROVEMENTS:

  * Add missing HTTP transport configuration options
  * Add `modulo` function for performing modulo math

BUG FIXES:

  * Default transport max idle connections based on `GOMAXPROCS`
  * Read `VAULT_*` envvars before finalizing [GH-914, GH-916]
  * Register `[]*KeyPair` as a gob [GH-893]

## v0.18.1 (February 7, 2017)

IMPROVEMENTS:

  * Add support for tagged addresses and metadata [GH-863]
  * Add `.exe` extension to Windows binaries [GH-875]
  * Add support for customizing the low-level transport details for Consul and
      Vault [GH-880, GH-877]
  * Read token from `~/.vault-token` if it exists [GH-878, GH-884]

BUG FIXES:

  * Resolve an issue with filters on health service dependencies [GH-857]
  * Restore ability to reload configurations from disk [GH-866]
  * Move `env` back to a helper function [GH-882]

    This was causing a lot of issues for users, and it required many folks to
    re-write their templates for the small benefit of people running in
    de-duplicate mode who did not understand the trade-offs. The README is now
    updated with the trade-offs of running in dedup mode and the expected `env`
    behavior has been restored.

  * Do not loop indefinitely if the dedup manager is unable to acquire a lock
      [GH-864]


## v0.18.0 (January 20, 2017)

NEW FEATURES:

  * Add new template function `keyExists` for determining if a key is present.
      See the breaking change notice before for more information about the
      motivation for this change.

  * Add `scratch` for storing information across a template invocation. Scratch
      is especially useful when saving a computed value to use it across a
      template. Scratch values are not shared across multiple templates and are
      not persisted between template invocations

  * Add support for controlling retry behavior for failed communications to
      Consul or Vault. By default, Consul Template will now retry 5 times before
      returning an error. The backoff timing and number of attempts can be tuned
      using the CLI or a configuration file.

  * Add `executeTemplate` function for executing a defined template.

  * Add `base64Decode`, `base64Encode`, `base64URLDecode`, and `base64URLEncode`
      functions for working with base64 encodings.

  * Add `containsAll`, `containsAny`, `containsNone`, and `containsNotAll`
      functions for easy filtering of multiple tag selections.

BREAKING CHANGES:

  * Consul Template now **blocks on `key` queries**. The previous behavior was
      to always pass through, allowing users to use the existence of a key as
      a source of control flow. This caused confusion among many users, so we
      have restored the expected behavior of blocking on a `key` query, but have
      added `keyExists` to check for the existence of a key. Note that the
      `keyOrDefault` function remains unchanged and will not block if the value
      is nil, as expected.

  * The `vault` template function has been removed. This has been deprecated
      with a warning since v0.14.0.

  * A shell is no longer assumed for Template commands. Previous versions of
      Consul Template assumed `/bin/sh` (`cmd` on Windows) as the parent
      process for the template command. Due to user requests and a desire to
      customize the shell, Consul Template no longer wraps the command in a
      shell. For most commands, this change will be transparent. If you were
      utilizing shell-specific functions like `&&`, `||`, or conditionals, you
      will need to wrap you command in a shell, for example:

    ```shell
    -template "in.tpl:out.tpl:/bin/bash -c 'echo a || b'"
    ```

    or

    ```hcl
    template {
      command = "/bin/bash -c 'echo a || b'"
    }
    ```

  * The `env` function is now treated as a dependency instead of a helper. For
      most users, there will be no impact.

  * This release is compiled with Golang v1.8. We do not expect this to cause
      any issues, but it is worth calling out.

DEPRECATIONS:

  * `.Tags.Contains` is deprecated. Templates should make use of the built-in
      `in` and `contains` functions instead. For example:

    ```liquid
    {{ if .Tags.Contains "foo" }}
    ```

    becomes:

    ```liquid
    {{ if .Tags | contains "foo" }}
    ```

    or:

    ```liquid
    {{ if "foo" | in .Tags }}
    ```

  * `key_or_default` has been renamed to `keyOrDefault` to better align with
      Go's naming structure. The old method is aliased and will remain until a
      future release.

  * Consul-specific CLI options are now prefixed with `-consul-`:

    * `-auth` is now `-consul-auth`
    * `-ssl-(.*)` is now `-consul-ssl-$1`
    * `-retry` is now `-consul-retry` and has been broken apart into more
      specific CLI options.

  * Consul-specific configuration options are now nested under a stanza. For
    example:

    ```hcl
    auth {
      username = "foo"
      password = "bar"
    }
    ```

    becomes:

    ```hcl
    consul {
      auth {
        username = "foo"
        password = "bar"
      }
    }
    ```

    This applies to the `auth`, `retry`, `ssl`, and `token` options.

IMPROVEMENTS:

  * Add CLI support for all SSL configuration options for both Consul and Vault.
    Vault options are identical to Consul but with `vault-` prefix. Includes
    the addition of `ssl-ca-path` to be consistent with file-based configuration
    options.

    * `ssl` `vault-ssl` (Enable)
    * `ssl-verify` `vault-ssl-verify`
    * `ssl-cert` `vault-ssl-cert`
    * `ssl-key` `vault-ssl-key`
    * `ssl-ca-cert` `vault-ssl-ca-cert`
    * `ssl-ca-path` `vault-ssl-ca-path`
    * `ssl-server-name` `vault-ssl-server-name`

  * Add `-consul-ssl-server-name`
  * Add `-consul-ssl-ca-path`
  * Add `-consul-retry`
  * Add `-consul-retry-attempts`
  * Add `-consul-retry-backoff`
  * Add `-vault-retry`
  * Add `-vault-retry-attempts`
  * Add `-vault-retry-backoff`
  * Add support for `server_name` option for TLS configurations to allow
      specification of the expected certificate common name.
  * Add `-vault-addr` CLI option for specifying the Vault server address
      [GH-740, GH-747]
  * Add tagged addresses to Node structs
  * Add support for multiple `-config` flags [GH-773, GH-751]
  * Add more control over template command execution
  * Add a way to programatically track the dependencies a particular template
      is blocked on [GH-799]

BUG FIXES:

  * Fix `-renew-token` flag not begin honored on the CLI [GH-741, GH-745]
  * Allow `*` in key names [GH-789, GH-755]

## v0.16.0 (September 22, 2016)

NEW FEATURES:

  * **Exec Mode!** Consul Template can now act as a faux-supervisor for
      applications. Please see the [Exec Mode](README.md#exec-mode)
      documentation for more information.
  * **Vault Token Unwrapping!** Consul Template can now unwrap Vault tokens that
      have been wrapped using Vault's cubbyhole response wrapping. Simply add
      the `unwrap_token` option to your Vault configuration stanza or pass in
      the `-vault-unwrap-token` command line flag.

BREAKING CHANGES:

  * Consul Template no longer terminates on SIGTERM or SIGQUIT. Previous
      versions were hard-coded to listen for SIGINT, SIGTERM, and SIGQUIT. This
      value is now configurable, and the default is SIGINT. SIGQUIT will trigger
      a core dump in accordance with similar programs. SIGTERM is no longer
      listened.
  * Consul Template now exits on irrecoverable Vault errors such as failing to
      renew a token or lease.

DEPRECATIONS:

  * The `vault.renew` option has been renamed to `vault.renew_token` for added
      clarity. This is backwards-compatible for this release, but will be
      removed in a future release, so please update your configurations
      accordingly.

IMPROVEMENTS:

  * Permit commas in key prefix names [GH-669]
  * Add configurable kill and reload signals [GH-686]
  * Add a command line flag for controlling whether a provided Vault token will
      be renewed [GH-718]

BUG FIXES:

  * Allow variadic template function for `secret` [GH-660, GH-662]
  * Always log in UTC time
  * Log milliseconds [GH-676, GH-674]
  * Maintain template ordering [GH-683]
  * Add `Service` address to catalog node response [GH-687]
  * Do not require trailing slashes [GH-706, GH-713]
  * Wait for all existing dedup acquire attempts to finish [GH-716, GH-677]


## v0.15.0.dev (June 9, 2016)

BREAKING CHANGES:

  * **Removing reaping functionality** [GH-628]

IMPROVEMENTS:

  * Allow specifying per-template delimiters [GH-615, GH-389]
  * Allow specifying per-template wait parameters [GH-589, GH-618]
  * Switch to actually vendoring dependencies
  * Add support for writing data [GH-652, GH-492]

BUG FIXES:

  * Close open connections when reloading configuration [GH-591, GH-595]
  * Do not share catalog nodes [GH-611, GH-572, GH-603]
  * Properly handle empty string in ParseUint [GH-610, GH-609]
  * Cache Vault's _original_ lease duration [5b955a8]
  * Use decimal division for calculating Vault lease durations [87d61d9]
  * Load VAULT_TOKEN environment variable [2431448]
  * Properly clean up quiescence timers when using multiple templates [GH-616]
  * Print a nice error if K/V cannot be exploded [GH-617, GH-596]
  * Update documentation about symlinks [GH-579]
  * Properly parse file permissions in mapstructure [GH-626]

## v0.14.0 (March 7, 2016)

DEPRECATIONS:

  * The `vault` template API function has been renamed to `secret` to be in line
    with other tooling. The `vault` API function will continue to work but will
    print a warning to the log file. A future release of Consul Template will
    remove the `vault` API.

NEW FEATURES:

  * Add `secrets` template API for listing secrets in Vault. Please note this
    requires Vault 0.5+ and the secret backend must support listing. Please see
    the Vault documentation for more information [GH-270]

IMPROVEMENTS:

  * Allow passing any kind of object to `toJSON` in the template. Previously
    this was restricted to key-value maps, but that restriction is now removed.
    [GH-553]

BUG FIXES:

  * Parse file permissions as a string in JSON [GH-548]
  * Document how to reload config with signals [GH-522]
  * Stop all dependencies when reloading the running/watcher [GH-534, GH-568]

## v0.13.0 (February 18, 2016)

BUG FIXES:

  * Compile with go1.6 to avoid race [GH-442]
  * Switch to using a pooled transport [GH-546]

## v0.12.2 (January 15, 2016)

BUG FIXES:

  * Fixed an issue when running as PID 1 in a Docker container where Consul
    Template could consume CPU and spuriously think its spwaned sub-processes
    had failed [GH-511]

## v0.12.1 (January 7, 2016)

IMPROVEMENTS:

  * Add support for math operations on uint types [GH-483, GH-484]
  * Make check information available through health service [GH-490]

BUG FIXES:

  * Store vault data on the dependency and handle an error where a failed
    lease renewal would result in `<no data>` in the rendered template. Please
    note, there is a bug in Vault 0.4 with respect to lease renewals that makes
    it inoperable with Consul Template. Please either use Vault 0.3 or wait
    until Vault 0.5 is released (the bug has already been fixed on master).
    [GH-468, GH-493, GH-504]


## v0.12.0 (December 10, 2015)

BREAKING CHANGES:

  * Add support for checking if a node is in maintenance mode [GH-477, GH-455]

    Previously, Consul Template would report nodes in maintenance mode as
    "critical". They will now report as "maintenance" so users can perform more
    detailed filtering. It is unlikely, but if you were filtering critical
    services, nodes/services in maintenance mode will no longer be included.


FEATURES:

  * Add support for de-duplication mode. In de-duplication mode, Consul Template
    uses leader election to elect one Consul Template process to render a
    template. The results of this template are rendered into Consul's key-value
    store, and other templates pull from the pre-rendered template. This option
    is off by default, but it is highly recommended that the option is enabled
    for clusters with a high load factor (number of templates x number of
    dependencies per template). [GH-465]
  * Add support for automatically reaping child processes. This is very useful
    when running Consul Template as PID 1 (like in a Docker container) when no
    init system is present. The option is configurable, but it defaults to "on"
    when the Consul Template process is PID 1. [GH-428, GH-479]


IMPROVEMENTS:

  * Use the `renew-self` endpoint instead of `renew` for renewing the token
    [GH-450]
  * Allow existing templates to be backed up before writing the new one [GH-464]
  * Add support for TLS/SSL mutual authentication [GH-448]
  * Add support for checking if a node is in maintenance mode [GH-477, GH-455]


## v0.11.1 (October 26, 2015)

FEATURES:

  * Accept "unix" as an argument to `timestamp` to generate a unix
    timestamp [GH-422]

IMPROVEMENTS:

  * Make `Path` a public field on the vault secret dependency so other libraries
    can access it

BUG FIXES:

  * Ensure there is a newline at the end of the version output
  * Update README development instructions [GH-423]
  * Adjust error messages so that data does not always "come from Consul"
  * Fix race conditions in tests
  * Update the `LastContact` value for non-Consul dependencies to always
    return 0 [GH-432, GH-433]
  * Always use `DefaultConfig()` in tests to find issues
  * Fix broken math functions - previously add, subtract, multiply, and divide
    for integers would perform the operation on only the first operand
    [GH-430, GH-435]
  * Renew the vault token based off of the auth, not the secret [GH-443]
  * Remove noisy log message [GH-445]


## v0.11.0 (October 9, 2015)

BREAKING CHANGES:

  * Allow configuration of destination file permissions [GH-415, GH-358]

    Previously, Consul Template would inspect the file at the destination path
    and mirror those file permissions, if a file existed. If a file did not
    exist, Consul Template would render the file with 0644 permissions. This was
    acceptable behavior in a pre-Vault world, but now that Consul Template is
    capable of rendering secrets, there is a desire for increased security. As
    such, Consul Template **no longer mirrors existing destination file
    permissions**. Instead, users can specify the file permissions in the
    configuration file. Please see the README for examples. If you were
    previously relying on an existing file's file permissions to enfore the
    destination file permissions, you must switch to specifying the file
    permissions in the configuration file. If you were not dependent on this
    behavior, nothing has changed; the default value is still 0644.

FEATURES:

  * Add `in` and `contains` functions for checking if a slice or array contains
    a given value [GH-366]
  * Add `add` function for calculating the sum of integers/floats
  * Add `subtract` function for calculating the difference of integers/floats
  * Add `multiply` function for calculating the product of integers/floats
  * Add `divide` function for calculating the division of integers/floats

IMPROVEMENTS:

  * Sort serivces by ID as well
  * Add a mechanism for renewing the given Vault token [GH-359, GH-367]
  * Default max-stale to 1s - this severely reduces the load on the Consul
    leader by allowing followers to respond to API requests [GH-386, GH-397]
  * Add GPG signing for SHASUMS on new releases
  * Push watcher errors down to the client in `once` mode [GH-361, GH-418]

BUG FIXES:

  * Set ssl in the CLI [GH-321]
  * **Regression** - Reload configuration on SIGHUP [GH-332]
  * Remove port option from `service` query and documentation - it was unused
    and legacy, but was causing issues and confusion [GH-333]
  * Return the empty value when no parsable value is given [GH-353]
  * Start with a blank configuration when reloading via SIGHUP [GH-393, GH-394]
  * Use an int64 instead of an int to loop function [GH-401, GH-402]
  * Do not remove the Windows file if it exists [GH-378]

## v0.10.0 (June 9, 2015)

FEATURES:

  * Add `plugin` and plugin ecosystem
  * Add `parseBool` function for parsing strings into booleans (GH-312)
  * Add `parseFloat` function for parsing strings into float64 (GH-312)
  * Add `parseInt` function for parsing strings into int64 (GH-312)
  * Add `parseUint` function for parsing strings into uint64 (GH-312)
  * Add `explode` function for exploding the result of `tree` or `ls` into a
    deeply nested  hash (GH-311)
  * Add `toJSON` and `toJSONPretty` function for exporting the result of `tree`
    or `ls`  into a JSON hash (GH-311)
  * Add `toYAML` function for exporting the result of `tree` or `ls` into a
    YAML document (GH-311)
  * Add `node` function for querying nodes (GH-306, GH-309)
  * Add `split` function for splitting a string on a separator (GH-285)
  * Add `join` function for joining a string slice on a given key (GH-285)
  * Add `pid_file` configuration and command line option for specifying the
    location of a pid file on disk (GH-281, GH-286)

IMPROVEMENTS:

  * Allow setting log_level via the configuration file (CLI still take
    precedence if specified)
  * Improve error reporting when loading multiple configs by including the path
    on the configuration file that had an error (GH-275)
  * Add a timeout around command execution to prevent hanging (GH-283)
  * Read Vault/Consul environment variables for the config (GH-307, GH-308)

BUG FIXES:

  * Properly merge "default" config values with user-supplied values (GH-271)


## v0.9.0 (April 29, 2015)

FEATURES:

  * Add Vault functionality for querying secrets from Vault (GH-264)
  * Add `regexMatch` template helper to determine if a result matches the given
    regular expressions (GH-246)
  * Add support for `ssl-cert` and `ss-ca-cert` options (GH-255)

IMPROVEMENTS:

  * Expand `byTag` to accept catalog services as well (GH-249, GH-250)
  * Allow catalog service tags to use the `.Contains` function (GH-261)

BUG FIXES:

  * Send the standard error of commands back over the standard error of
    Consul Template (GH-253, GH-254)
  * Allow specifying `-v` in addition to `-version` to get the version output

## v0.8.0 (March 30, 2015)

FEATURES:

  * Add `.Size()` so the watcher can report its size (GH-206)
  * Add `byKey` template helper to group the results of a `tree` function by
    their containing directory (GH-207, GH-209, GH-241)
  * Add `timestamp` template function for returning the current timestamp with
    the ability to add custom formatting (GH-225, GH-230)
  * Add `loop` template function for iteration (GH-238, GH-221)

IMPROVEMENTS:

  * Expose `LastIndex` and `ReceivedData` from the Watcher
  * Add unimplemented KV fields (GH-203)
  * Warn the user if there are a large number of dependencies (GH-205)
  * Extend documentation on how health service dependencies are downloaded from
    Consul (GH-212)
  * Allow empty configuration directories (GH-217)
  * Document caveats around using `parseJSON` during multi-evaluation
  * Print the final configuration as JSON in debug mode (GH-231)
  * Export certain environment variables when executing commands that are read
    by other Consul tooling or in your scripts (GH-232) - see the README for
    more information
  * Adjust logging to be less noisy without compromising information (GH-242)

BUG FIXES:

  * Properly filter services by their type (GH-210, GH-212)
  * Return an error if extra arguments are given on the command line (GH-227)
  * Do not overwrite given configuration with the default options (GH-228, GH-219)
  * Check for the correct conditions when using basic authentication (GH-220)
  * Remove unused code paths for clarity (GH-242)
  * Remove race condition in templates when called concurrently (GH-242)
  * Remove race condition in test suite (GH-242)
  * Force a refresh if Consul's WaitIndex is less than our current value (GH-242)
  * Avoid pushing data onto the watcher when the view has been stopped (GH-242)
  * Do not accept data in the runner for an unwatched dependency (GH-198, GH-242)

## v0.7.0 (February 19, 2015)

BREAKING CHANGES:

  * Remove `ssl` configuration option from templates - use an `ssl`
    configuration block with `enabled = true` instead
  * Remove `ssl_no_verify` configuration option from templates - use an `ssl`
    configuration block with `verify = false` instead
  * Restructure CLI `-ssl-no-verify` to `-ssl-verify` - to disable SSL
    certification validation on the command line, use `-ssl-verify=false`
  * Remove `auth` configuration option from templates - use an `auth`
    configuration block with `enabled = true` combined with `username = ...` and
    `password = ...` inside the block instead

FEATURES:

  * Add support for logging to syslog (GH-163)
  * Add `log_level` as a configuration file option
  * Add `-log-level` as a CLI option

IMPROVEMENTS:

  * Use a default retry interval of 5s (GH-190) - this value has been (and will
    remain) configurable since v0.5.0, but the default value has changed from 0
    to 5s
  * Use a service's reported address if given (GH-185, GH-186)
  * Add new `NodeAddress` field to health services to always include the node's
    address
  * Return errors up the watcher's error channel so other libraries can
    determine what to do with the error instead of swallowing it (GH-196)
  * Move SSL and authentication options into their own configuration blocks in
    the HCL
  * Add new `watch.WaitVar` for parsing Wait structs via Go's flag parsing
    library.
  * Extract logging components into their own library for sharing (GH-199)

BUG FIXES:

  * Return errors instead of nil in catalog nodes and key prefix dependencies
    (GH-192)
  * Allow Consul Template to exit when running in `once` mode and templates have
    not changed (GH-188)
  * Raise an error when specifying a non-existent option in the configuration
    file (GH-197)
  * Use an RWLock when accessing information in the Brain to improve performance
  * Improve debugging output and consistency
  * Remove unused Brain functions
  * Remove unused documentation items
  * Use the correct default values for `-ssl` and `-retry` on the CLI

## v0.6.5 (February 5, 2015)

FEATURES:

  * Add `-max-stale` to specify Consul Template may talk to non-leader Consul
    nodes if they are less than the maximum stale value (GH-183)

BUG FIXES:

  * Fix a concurrency bug in the Brain (GH-180)
  * Add a better queue-draining mechanism for templates that have a large number
    of dependencies (GH-184)

## v0.6.1 (February 2, 2015)

IMPROVEMENTS:

  * Allow watcher to use buffered channels so we do not block when multiple
    dependencies return data (GH-176)
  * Buffer results from the watcher to reduce the number of CPU cycles (GH-168
    and GH-178)

BUG FIXES:

  * Handle the case where reloading via SIGHUP would cause an error (GH-175 and
    GH-177)
  * Return errors to the template when parsing a key fails (GH-170)
  * Expand the list of possible values for keys to non-ASCII fields (the `@` is
    still a restricted character because it denotes the datacenter) (GH-170)
  * Diff missing dependencies during the template render to avoid creating
    extra watchers (GH-169)
  * Improve debugging output (GH-169)

## v0.6.0 (January 20, 2015)

FEATURES:

  * Implement n-pass evaluation (GH-64) - templates are now evaluated N+1 times
    to properly accumulate dependencies and build the graph properly

BREAKING CHANGES:

  * Remove `storeKeyPrefix` template function - it has been replaced with `ls`
    and/or `tree` and was deprecated in 0.2.0
  * Remove `Key()` from dependency interface

IMPROVEMENTS:

  * Switch to using `hashicorp/consul/api` instead of `armon/consul-api`
  * Add support for communicating with Consul via HTTPS/SSL (GH-143)
  * Add support for communicating with Consul via BasicAuth (GH-147)
  * Quiesce on a per-template basis

BUG FIXES:

  * Reduce memory footprint when running with a large number of templates by
    using a single context instead of separate template contexts for each
    template
  * Improve test coverage
  * Improve debugging output
  * Correct tag deep copy that could result in 2N-1 tags (GH-155)
  * Return an empty slice when parsing an empty JSON file
  * Update README documentation

## v0.5.1 (December 25, 2014)

BUG FIXES:

  * Parse Retry values in the config (GH-136)
  * Remove `util` package as it is a code smell and separate `Watcher` and
    `Dependency` structs and functions into their own packages for re-use
    (GH-137)

## v0.5.0 (December 19, 2014)

FEATURES:

  * Reload configuration on `SIGHUP`
  * Add `services` template function for listing all services and associated
    tags in the Consul catalog (GH-77)

BUG FIXES:

  * Do not execute the same command more than once in one run (GH-112)
  * Do not exit when Consul is unavailable (GH-103)
  * Accept configuration files as a valid option to `-config` (GH-126)
  * Accept Windows drive letters in template paths (GH-78)
  * Deep copy and sort data returned from Consul API (specifically tags)
  * Run commands even if not all templates have received data (GH-119)

IMPROVEMENTS:

  * Add support for more complex service health filtering (GH-116)
  * Add support for specifying a `-retry` interval for Consul timeouts and
    connection errors (GH-22)
  * Use official HashiCorp multierror package for errors
  * Gracefully stop watchers on interrupt
  * Add support for Go 1.4
  * Improve test coverage around retrying failures

## v0.4.0 (December 10, 2014)

FEATURES:

  * Add `env` template function for reading an environment variable in the
    current process into the template
  * Add `regexReplaceAll` template function

BUG FIXES:

  * Fix documentation examples
  * Fix `golint` and `go vet` errors
  * Fix a panic when Consul returned empty query metadata
  * Allow colons in key prefixes (`ls` and `tree` receive this by proxy)
  * Allow `parseJSON` to handle top-level JSON objects
  * Filter empty keys in `tree` and `ls` (folder nodes)

IMPROVEMENTS:

  * Merge multiple configuration template definitions when a configuration
    directory is specified

## v0.3.1 (November 24, 2014)

BUG FIXES:

  * Allow colons in key names (GH-67)
  * Fix a documentation bug in the README in the Varnish example (GH-82)
  * Attempt to render templates before starting the watcher - this fixes an
    issue where a template that declared no Consul dependencies would never be
    rendered (GH-85)
  * Update inline Go documentation for better clarity

IMPROVEMENTS:

  * Fix all issues raised by `go vet`
  * Update packaging script to fix ZSHisms and use awk for clarity

## v0.3.0 (November 13, 2014)

FEATURES:

  * Added a `Contains` method to `Service.Tags`
  * Added support for specifying a configuration directory in `-config`, in
    addition to a file
  * Added support for querying all nodes in Consul's catalog with the `nodes`
    template function

BUG FIXES:

  * Update README documentation to clarify that `service` dependencies default
    to the current datacenter if one is not explicitly given
  * Ignore empty keys that are returned from an `ls` call (GH-54)
  * When writing a file atomicly, ensure the drive is the same (GH-58)
  * Run all commands before exiting - previously if a single command failed in
    a multi-template environment, the other commands would not execute, but
    Consul Template would return

IMPROVEMENTS:

  * Added support for querying all `service` nodes by passing an additional
    parameter to `service`

## v0.2.0 (November 4, 2014)

FEATURES:

  * Added helper for decoding a result as JSON using the `parseJSON` pipe
    function
  * Added support for reading and watching changes from a file using the `file`
    template function
  * Added helper for sorting service entires by a particular tag
  * Added helper function `toLower()` for converting a string to lowercase
  * Added helper function `toTitle()` for converting a string to titlecase
  * Added helper function `toUpper()` for converting a string to uppercase
  * Added helper function `replaceAll()` for replacing occurrences of a
    substring with a new string
  * Added `tree` function for returning all key prefixes recursively
  * Added `ls` function for returning all keys in the top-level prefix (but not
    deeply nested ones)

BUG FIXES:

  * Remove prefixes from paths when querying a key prefix

IMPROVEMENTS:

  * Moved shareable functions into a util module so other libraries can benefit
  * Make Path a public field on Template
  * Added more examples and documentation to the README

DEPRECATIONS:

  * `keyPrefix` is deprecated in favor or `tree` and `ls` and will be removed in
  the next major release


## v0.1.1 (October 28, 2014)

BUG FIXES:

  * Fixed an issue where help output was displayed twice when specifying the
    `-h` flag
  * Added support for specifyiny forward slashes (`/`) in service names
  * Added support for specifying underscores (`_`) in service names
  * Added support for specifying dots (`.`) in tag names

IMPROVEMENTS:

  * Added support for Travis CI
  * Fixed numerous typographical errors
  * Added more documentation, including an FAQ in the README
  * Do not return an error when a template has no dependencies. See GH-31 for
    more background and information
  * Do not render templates if they have the same content
  * Do not execute commands if the template on disk would not be changed

## v0.1.0 (October 21, 2014)

  * Initial release
