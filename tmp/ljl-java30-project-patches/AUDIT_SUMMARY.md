# Audit Summary

Validation target: 30 Java project-level migrated CVE patches.

Validation standard: patch each sample into a clean downstream project copy, then run the local CVE runner from the patched project and require the marker `actual=1`.

Result:

- Checked: 30
- Passed: 30
- Failed: 0
- Unique downstream repositories: 30
- Downstream repositories: Apache only
- Evidence file: `logs/apply_run_all.json`
- Elapsed validation time: 64.11 seconds

Per-sample validation procedure:

1. copy clean sparse repository from the downstream repo cache;
2. run `git apply <patch>`;
3. run `python3 .cve_poc_local/run_local_cve_poc.py <CVE>`;
4. require `apply_rc=0`;
5. require `run_rc=0`;
6. require `pass=true`;
7. require `actual="1"`;
8. require `exit_code=0`.

Library coverage:

- apache-commons-beanutils: 3
- apache-commons-collections: 3
- apache-commons-fileupload: 2
- apache-commons-io: 3
- apache-shiro: 3
- apache-xmlbeans: 2
- dom4j: 3
- jackson: 3
- jetty: 3
- log4j: 3
- netty: 2

Downstream repositories:

- apache/accumulo
- apache/ambari
- apache/atlas
- apache/bookkeeper
- apache/brooklyn-server
- apache/beam
- apache/cxf
- apache/geode
- apache/jackrabbit
- apache/camel
- apache/kylin
- apache/calcite
- apache/druid
- apache/dubbo
- apache/gobblin
- apache/flink
- apache/hadoop
- apache/hive
- apache/jena
- apache/james-project
- apache/hop
- apache/poi
- apache/hbase
- apache/helix
- apache/ignite
- apache/jmeter
- apache/karaf
- apache/knox
- apache/maven
- apache/ranger
