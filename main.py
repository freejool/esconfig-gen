import os
import yaml
import shutil
import sys

conf = {
    "master_node_name_format": "master-node{:02d}",
    "data_node_name_format": "data-node{:02d}",
    "master_node_count": 3,  # 主节点总数
    "data_node_count": 3,  # 每个vm的数据节点数
    "vm_num": 4,  # 虚拟机数量，虚拟机数量需大于主节点数量，保证一个虚拟机拥有 <= 1个主节点
    "vm_ips": ["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"],  # 虚拟机ip
    "vm_name_format": "vm{:02d}",
    "cluster.name": "mycluster",
    "output_path": "./config",
    "xpack_security": True,
    "path.data": "./data",
    "path.logs": "./logs",
    "master_jvm_options": ["-Xms512m", "-Xmx512m"],
    "data_jvm_options": ["-Xms512m", "-Xmx512m"],
    "bootstrap.memory_lock": True,
    "log4j2.properties": """
status = error

appender.console.type = Console
appender.console.name = console
appender.console.layout.type = PatternLayout
appender.console.layout.pattern = [%d{ISO8601}][%-5p][%-25c{1.}] [%node_name]%marker %m%n

######## Server JSON ############################
appender.rolling.type = RollingFile
appender.rolling.name = rolling
appender.rolling.fileName = ${sys:es.logs.base_path}${sys:file.separator}${sys:es.logs.cluster_name}_server.json
appender.rolling.layout.type = ESJsonLayout
appender.rolling.layout.type_name = server

appender.rolling.filePattern = ${sys:es.logs.base_path}${sys:file.separator}${sys:es.logs.cluster_name}-%d{yyyy-MM-dd}-%i.json.gz
appender.rolling.policies.type = Policies
appender.rolling.policies.time.type = TimeBasedTriggeringPolicy
appender.rolling.policies.time.interval = 1
appender.rolling.policies.time.modulate = true
appender.rolling.policies.size.type = SizeBasedTriggeringPolicy
appender.rolling.policies.size.size = 128MB
appender.rolling.strategy.type = DefaultRolloverStrategy
appender.rolling.strategy.fileIndex = nomax
appender.rolling.strategy.action.type = Delete
appender.rolling.strategy.action.basepath = ${sys:es.logs.base_path}
appender.rolling.strategy.action.condition.type = IfFileName
appender.rolling.strategy.action.condition.glob = ${sys:es.logs.cluster_name}-*
appender.rolling.strategy.action.condition.nested_condition.type = IfAccumulatedFileSize
appender.rolling.strategy.action.condition.nested_condition.exceeds = 2GB
################################################
######## Server -  old style pattern ###########
appender.rolling_old.type = RollingFile
appender.rolling_old.name = rolling_old
appender.rolling_old.fileName = ${sys:es.logs.base_path}${sys:file.separator}${sys:es.logs.cluster_name}.log
appender.rolling_old.layout.type = PatternLayout
appender.rolling_old.layout.pattern = [%d{ISO8601}][%-5p][%-25c{1.}] [%node_name]%marker %m%n

appender.rolling_old.filePattern = ${sys:es.logs.base_path}${sys:file.separator}${sys:es.logs.cluster_name}-%d{yyyy-MM-dd}-%i.log.gz
appender.rolling_old.policies.type = Policies
appender.rolling_old.policies.time.type = TimeBasedTriggeringPolicy
appender.rolling_old.policies.time.interval = 1
appender.rolling_old.policies.time.modulate = true
appender.rolling_old.policies.size.type = SizeBasedTriggeringPolicy
appender.rolling_old.policies.size.size = 128MB
appender.rolling_old.strategy.type = DefaultRolloverStrategy
appender.rolling_old.strategy.fileIndex = nomax
appender.rolling_old.strategy.action.type = Delete
appender.rolling_old.strategy.action.basepath = ${sys:es.logs.base_path}
appender.rolling_old.strategy.action.condition.type = IfFileName
appender.rolling_old.strategy.action.condition.glob = ${sys:es.logs.cluster_name}-*
appender.rolling_old.strategy.action.condition.nested_condition.type = IfAccumulatedFileSize
appender.rolling_old.strategy.action.condition.nested_condition.exceeds = 2GB
################################################

rootLogger.level = info
rootLogger.appenderRef.console.ref = console
rootLogger.appenderRef.rolling.ref = rolling
rootLogger.appenderRef.rolling_old.ref = rolling_old

######## Deprecation JSON #######################
appender.deprecation_rolling.type = RollingFile
appender.deprecation_rolling.name = deprecation_rolling
appender.deprecation_rolling.fileName = ${sys:es.logs.base_path}${sys:file.separator}${sys:es.logs.cluster_name}_deprecation.json
appender.deprecation_rolling.layout.type = ESJsonLayout
appender.deprecation_rolling.layout.type_name = deprecation
appender.deprecation_rolling.layout.esmessagefields=x-opaque-id
appender.deprecation_rolling.filter.rate_limit.type = RateLimitingFilter

appender.deprecation_rolling.filePattern = ${sys:es.logs.base_path}${sys:file.separator}${sys:es.logs.cluster_name}_deprecation-%i.json.gz
appender.deprecation_rolling.policies.type = Policies
appender.deprecation_rolling.policies.size.type = SizeBasedTriggeringPolicy
appender.deprecation_rolling.policies.size.size = 1GB
appender.deprecation_rolling.strategy.type = DefaultRolloverStrategy
appender.deprecation_rolling.strategy.max = 4

appender.header_warning.type = HeaderWarningAppender
appender.header_warning.name = header_warning
#################################################
######## Deprecation -  old style pattern #######
appender.deprecation_rolling_old.type = RollingFile
appender.deprecation_rolling_old.name = deprecation_rolling_old
appender.deprecation_rolling_old.fileName = ${sys:es.logs.base_path}${sys:file.separator}${sys:es.logs.cluster_name}_deprecation.log
appender.deprecation_rolling_old.layout.type = PatternLayout
appender.deprecation_rolling_old.layout.pattern = [%d{ISO8601}][%-5p][%-25c{1.}] [%node_name]%marker %m%n

appender.deprecation_rolling_old.filePattern = ${sys:es.logs.base_path}${sys:file.separator}${sys:es.logs.cluster_name}\
  _deprecation-%i.log.gz
appender.deprecation_rolling_old.policies.type = Policies
appender.deprecation_rolling_old.policies.size.type = SizeBasedTriggeringPolicy
appender.deprecation_rolling_old.policies.size.size = 1GB
appender.deprecation_rolling_old.strategy.type = DefaultRolloverStrategy
appender.deprecation_rolling_old.strategy.max = 4
#################################################
logger.deprecation.name = org.elasticsearch.deprecation
logger.deprecation.level = deprecation
logger.deprecation.appenderRef.deprecation_rolling.ref = deprecation_rolling
logger.deprecation.appenderRef.deprecation_rolling_old.ref = deprecation_rolling_old
logger.deprecation.appenderRef.header_warning.ref = header_warning
logger.deprecation.additivity = false

######## Search slowlog JSON ####################
appender.index_search_slowlog_rolling.type = RollingFile
appender.index_search_slowlog_rolling.name = index_search_slowlog_rolling
appender.index_search_slowlog_rolling.fileName = ${sys:es.logs.base_path}${sys:file.separator}${sys:es.logs\
  .cluster_name}_index_search_slowlog.json
appender.index_search_slowlog_rolling.layout.type = ESJsonLayout
appender.index_search_slowlog_rolling.layout.type_name = index_search_slowlog
appender.index_search_slowlog_rolling.layout.esmessagefields=message,took,took_millis,total_hits,types,stats,search_type,total_shards,source,id

appender.index_search_slowlog_rolling.filePattern = ${sys:es.logs.base_path}${sys:file.separator}${sys:es.logs\
  .cluster_name}_index_search_slowlog-%i.json.gz
appender.index_search_slowlog_rolling.policies.type = Policies
appender.index_search_slowlog_rolling.policies.size.type = SizeBasedTriggeringPolicy
appender.index_search_slowlog_rolling.policies.size.size = 1GB
appender.index_search_slowlog_rolling.strategy.type = DefaultRolloverStrategy
appender.index_search_slowlog_rolling.strategy.max = 4
#################################################
######## Search slowlog -  old style pattern ####
appender.index_search_slowlog_rolling_old.type = RollingFile
appender.index_search_slowlog_rolling_old.name = index_search_slowlog_rolling_old
appender.index_search_slowlog_rolling_old.fileName = ${sys:es.logs.base_path}${sys:file.separator}${sys:es.logs.cluster_name}\
  _index_search_slowlog.log
appender.index_search_slowlog_rolling_old.layout.type = PatternLayout
appender.index_search_slowlog_rolling_old.layout.pattern = [%d{ISO8601}][%-5p][%-25c{1.}] [%node_name]%marker %m%n

appender.index_search_slowlog_rolling_old.filePattern = ${sys:es.logs.base_path}${sys:file.separator}${sys:es.logs.cluster_name}\
  _index_search_slowlog-%i.log.gz
appender.index_search_slowlog_rolling_old.policies.type = Policies
appender.index_search_slowlog_rolling_old.policies.size.type = SizeBasedTriggeringPolicy
appender.index_search_slowlog_rolling_old.policies.size.size = 1GB
appender.index_search_slowlog_rolling_old.strategy.type = DefaultRolloverStrategy
appender.index_search_slowlog_rolling_old.strategy.max = 4
#################################################
logger.index_search_slowlog_rolling.name = index.search.slowlog
logger.index_search_slowlog_rolling.level = trace
logger.index_search_slowlog_rolling.appenderRef.index_search_slowlog_rolling.ref = index_search_slowlog_rolling
logger.index_search_slowlog_rolling.appenderRef.index_search_slowlog_rolling_old.ref = index_search_slowlog_rolling_old
logger.index_search_slowlog_rolling.additivity = false

######## Indexing slowlog JSON ##################
appender.index_indexing_slowlog_rolling.type = RollingFile
appender.index_indexing_slowlog_rolling.name = index_indexing_slowlog_rolling
appender.index_indexing_slowlog_rolling.fileName = ${sys:es.logs.base_path}${sys:file.separator}${sys:es.logs.cluster_name}\
  _index_indexing_slowlog.json
appender.index_indexing_slowlog_rolling.layout.type = ESJsonLayout
appender.index_indexing_slowlog_rolling.layout.type_name = index_indexing_slowlog
appender.index_indexing_slowlog_rolling.layout.esmessagefields=message,took,took_millis,doc_type,id,routing,source

appender.index_indexing_slowlog_rolling.filePattern = ${sys:es.logs.base_path}${sys:file.separator}${sys:es.logs.cluster_name}\
  _index_indexing_slowlog-%i.json.gz
appender.index_indexing_slowlog_rolling.policies.type = Policies
appender.index_indexing_slowlog_rolling.policies.size.type = SizeBasedTriggeringPolicy
appender.index_indexing_slowlog_rolling.policies.size.size = 1GB
appender.index_indexing_slowlog_rolling.strategy.type = DefaultRolloverStrategy
appender.index_indexing_slowlog_rolling.strategy.max = 4
#################################################
######## Indexing slowlog -  old style pattern ##
appender.index_indexing_slowlog_rolling_old.type = RollingFile
appender.index_indexing_slowlog_rolling_old.name = index_indexing_slowlog_rolling_old
appender.index_indexing_slowlog_rolling_old.fileName = ${sys:es.logs.base_path}${sys:file.separator}${sys:es.logs.cluster_name}\
  _index_indexing_slowlog.log
appender.index_indexing_slowlog_rolling_old.layout.type = PatternLayout
appender.index_indexing_slowlog_rolling_old.layout.pattern = [%d{ISO8601}][%-5p][%-25c{1.}] [%node_name]%marker %m%n

appender.index_indexing_slowlog_rolling_old.filePattern = ${sys:es.logs.base_path}${sys:file.separator}${sys:es.logs.cluster_name}\
  _index_indexing_slowlog-%i.log.gz
appender.index_indexing_slowlog_rolling_old.policies.type = Policies
appender.index_indexing_slowlog_rolling_old.policies.size.type = SizeBasedTriggeringPolicy
appender.index_indexing_slowlog_rolling_old.policies.size.size = 1GB
appender.index_indexing_slowlog_rolling_old.strategy.type = DefaultRolloverStrategy
appender.index_indexing_slowlog_rolling_old.strategy.max = 4
#################################################

logger.index_indexing_slowlog.name = index.indexing.slowlog.index
logger.index_indexing_slowlog.level = trace
logger.index_indexing_slowlog.appenderRef.index_indexing_slowlog_rolling.ref = index_indexing_slowlog_rolling
logger.index_indexing_slowlog.appenderRef.index_indexing_slowlog_rolling_old.ref = index_indexing_slowlog_rolling_old
logger.index_indexing_slowlog.additivity = false


appender.audit_rolling.type = RollingFile
appender.audit_rolling.name = audit_rolling
appender.audit_rolling.fileName = ${sys:es.logs.base_path}${sys:file.separator}${sys:es.logs.cluster_name}_audit.json
appender.audit_rolling.layout.type = PatternLayout
appender.audit_rolling.layout.pattern = {\
                "type":"audit", \
                "timestamp":"%d{yyyy-MM-dd'T'HH:mm:ss,SSSZ}"\
                %varsNotEmpty{, "node.name":"%enc{%map{node.name}}{JSON}"}\
                %varsNotEmpty{, "node.id":"%enc{%map{node.id}}{JSON}"}\
                %varsNotEmpty{, "host.name":"%enc{%map{host.name}}{JSON}"}\
                %varsNotEmpty{, "host.ip":"%enc{%map{host.ip}}{JSON}"}\
                %varsNotEmpty{, "event.type":"%enc{%map{event.type}}{JSON}"}\
                %varsNotEmpty{, "event.action":"%enc{%map{event.action}}{JSON}"}\
                %varsNotEmpty{, "authentication.type":"%enc{%map{authentication.type}}{JSON}"}\
                %varsNotEmpty{, "user.name":"%enc{%map{user.name}}{JSON}"}\
                %varsNotEmpty{, "user.run_by.name":"%enc{%map{user.run_by.name}}{JSON}"}\
                %varsNotEmpty{, "user.run_as.name":"%enc{%map{user.run_as.name}}{JSON}"}\
                %varsNotEmpty{, "user.realm":"%enc{%map{user.realm}}{JSON}"}\
                %varsNotEmpty{, "user.run_by.realm":"%enc{%map{user.run_by.realm}}{JSON}"}\
                %varsNotEmpty{, "user.run_as.realm":"%enc{%map{user.run_as.realm}}{JSON}"}\
                %varsNotEmpty{, "user.roles":%map{user.roles}}\
                %varsNotEmpty{, "apikey.id":"%enc{%map{apikey.id}}{JSON}"}\
                %varsNotEmpty{, "apikey.name":"%enc{%map{apikey.name}}{JSON}"}\
                %varsNotEmpty{, "origin.type":"%enc{%map{origin.type}}{JSON}"}\
                %varsNotEmpty{, "origin.address":"%enc{%map{origin.address}}{JSON}"}\
                %varsNotEmpty{, "realm":"%enc{%map{realm}}{JSON}"}\
                %varsNotEmpty{, "url.path":"%enc{%map{url.path}}{JSON}"}\
                %varsNotEmpty{, "url.query":"%enc{%map{url.query}}{JSON}"}\
                %varsNotEmpty{, "request.method":"%enc{%map{request.method}}{JSON}"}\
                %varsNotEmpty{, "request.body":"%enc{%map{request.body}}{JSON}"}\
                %varsNotEmpty{, "request.id":"%enc{%map{request.id}}{JSON}"}\
                %varsNotEmpty{, "action":"%enc{%map{action}}{JSON}"}\
                %varsNotEmpty{, "request.name":"%enc{%map{request.name}}{JSON}"}\
                %varsNotEmpty{, "indices":%map{indices}}\
                %varsNotEmpty{, "opaque_id":"%enc{%map{opaque_id}}{JSON}"}\
                %varsNotEmpty{, "x_forwarded_for":"%enc{%map{x_forwarded_for}}{JSON}"}\
                %varsNotEmpty{, "transport.profile":"%enc{%map{transport.profile}}{JSON}"}\
                %varsNotEmpty{, "rule":"%enc{%map{rule}}{JSON}"}\
                %varsNotEmpty{, "event.category":"%enc{%map{event.category}}{JSON}"}\
                }%n
# "node.name" node name from the `elasticsearch.yml` settings
# "node.id" node id which should not change between cluster restarts
# "host.name" unresolved hostname of the local node
# "host.ip" the local bound ip (i.e. the ip listening for connections)
# "event.type" a received REST request is translated into one or more transport requests. This indicates which processing layer generated the event "rest" or "transport" (internal)
# "event.action" the name of the audited event, eg. "authentication_failed", "access_granted", "run_as_granted", etc.
# "authentication.type" one of "realm", "api_key", "token", "anonymous" or "internal"
# "user.name" the subject name as authenticated by a realm
# "user.run_by.name" the original authenticated subject name that is impersonating another one.
# "user.run_as.name" if this "event.action" is of a run_as type, this is the subject name to be impersonated as.
# "user.realm" the name of the realm that authenticated "user.name"
# "user.run_by.realm" the realm name of the impersonating subject ("user.run_by.name")
# "user.run_as.realm" if this "event.action" is of a run_as type, this is the realm name the impersonated user is looked up from
# "user.roles" the roles array of the user; these are the roles that are granting privileges
# "apikey.id" this field is present if and only if the "authentication.type" is "api_key"
# "apikey.name" this field is present if and only if the "authentication.type" is "api_key"
# "origin.type" it is "rest" if the event is originating (is in relation to) a REST request; possible other values are "transport" and "ip_filter"
# "origin.address" the remote address and port of the first network hop, i.e. a REST proxy or another cluster node
# "realm" name of a realm that has generated an "authentication_failed" or an "authentication_successful"; the subject is not yet authenticated
# "url.path" the URI component between the port and the query string; it is percent (URL) encoded
# "url.query" the URI component after the path and before the fragment; it is percent (URL) encoded
# "request.method" the method of the HTTP request, i.e. one of GET, POST, PUT, DELETE, OPTIONS, HEAD, PATCH, TRACE, CONNECT
# "request.body" the content of the request body entity, JSON escaped
# "request.id" a synthentic identifier for the incoming request, this is unique per incoming request, and consistent across all audit events generated by that request
# "action" an action is the most granular operation that is authorized and this identifies it in a namespaced way (internal)
# "request.name" if the event is in connection to a transport message this is the name of the request class, similar to how rest requests are identified by the url path (internal)
# "indices" the array of indices that the "action" is acting upon
# "opaque_id" opaque value conveyed by the "X-Opaque-Id" request header
# "x_forwarded_for" the addresses from the "X-Forwarded-For" request header, as a verbatim string value (not an array)
# "transport.profile" name of the transport profile in case this is a "connection_granted" or "connection_denied" event
# "rule" name of the applied rule if the "origin.type" is "ip_filter"
# "event.category" fixed value "elasticsearch-audit"

appender.audit_rolling.filePattern = ${sys:es.logs.base_path}${sys:file.separator}${sys:es.logs.cluster_name}_audit-%d{yyyy-MM-dd}.json
appender.audit_rolling.policies.type = Policies
appender.audit_rolling.policies.time.type = TimeBasedTriggeringPolicy
appender.audit_rolling.policies.time.interval = 1
appender.audit_rolling.policies.time.modulate = true

logger.xpack_security_audit_logfile.name = org.elasticsearch.xpack.security.audit.logfile.LoggingAuditTrail
logger.xpack_security_audit_logfile.level = info
logger.xpack_security_audit_logfile.appenderRef.audit_rolling.ref = audit_rolling
logger.xpack_security_audit_logfile.additivity = false

logger.xmlsig.name = org.apache.xml.security.signature.XMLSignature
logger.xmlsig.level = error
logger.samlxml_decrypt.name = org.opensaml.xmlsec.encryption.support.Decrypter
logger.samlxml_decrypt.level = fatal
logger.saml2_decrypt.name = org.opensaml.saml.saml2.encryption.Decrypter
logger.saml2_decrypt.level = fatal

    """,
    "key_path": "./elastic-certificates.p12",
}


def add_master_conf(elasticsearch_yml: dict) -> None:
    elasticsearch_yml["node.master"] = True
    elasticsearch_yml["node.data"] = False


def add_data_conf(elasticsearch_yml: dict) -> None:
    elasticsearch_yml["node.master"] = False
    elasticsearch_yml["node.data"] = True


def add_common_conf(elasticsearch_yml: dict) -> None:
    elasticsearch_yml["cluster.name"] = conf["cluster.name"]
    elasticsearch_yml["bootstrap.memory_lock"] = conf["bootstrap.memory_lock"]
    elasticsearch_yml["cluster.initial_master_nodes"] = initial_master_nodes
    elasticsearch_yml["discovery.seed_hosts"] = discovery_seed_hosts
    if conf["xpack_security"]:
        elasticsearch_yml["xpack.security.enabled"] = True
        elasticsearch_yml["xpack.security.transport.ssl.enabled"] = True
        elasticsearch_yml["xpack.security.transport.ssl.verification_mode"] = (
            "certificate"
        )
        elasticsearch_yml["xpack.security.transport.ssl.keystore.path"] = conf[
            "key_path"
        ]
        elasticsearch_yml["xpack.security.transport.ssl.truststore.path"] = conf[
            "key_path"
        ]


if __name__ == "__main__":
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r") as f:
            print(f"using config file: {sys.argv[1]}")
            loaded = yaml.safe_load(f)
            delta = set(loaded) - set(conf)
            if len(delta) > 0:
                raise ValueError(f"Unknown keys: {delta}")
            conf.update(loaded)
    else:
        print("using default config")
        
    if conf["master_node_count"] > conf["vm_num"]:
        raise ValueError("虚拟机数量需大于主节点数量")
    config_output = {}
    cmd_output = []
    discovery_seed_hosts = conf["vm_ips"]
    initial_master_nodes = [
        conf["master_node_name_format"].format(s + 1)
        for s in range(conf["master_node_count"])
    ]

    master_allocated = 0
    data_allocated = 0
    data_total = conf["data_node_count"] * conf["vm_num"]

    for i in range(conf["vm_num"]):
        cmd = []
        vm_name = conf["vm_name_format"].format(i + 1)
        config_output[vm_name] = {}
        if master_allocated < conf["master_node_count"]:
            master_node_name = conf["master_node_name_format"].format(
                master_allocated + 1
            )
            elasticsearch_yml = {}
            add_common_conf(elasticsearch_yml)
            add_master_conf(elasticsearch_yml)
            elasticsearch_yml.update(
                {
                    "node.name": master_node_name,
                    "path.data": os.path.join(
                        conf["path.data"], vm_name, master_node_name
                    ),
                    "path.logs": os.path.join(
                        conf["path.logs"], vm_name, master_node_name
                    ),
                }
            )
            config_output[vm_name][master_node_name] = {
                "elasticsearch.yml": yaml.dump(elasticsearch_yml),
                "jvm.options": "\n".join(conf["master_jvm_options"]),
                "log4j2.properties": conf["log4j2.properties"],
            }
            master_allocated += 1
            conf_path = os.path.join(conf["output_path"], vm_name, master_node_name)
            cmd.append(f"ES_PATH_CONF={conf_path} bin/elasticsearch -d")
        for _ in range(conf["data_node_count"]):
            data_node_name = conf["data_node_name_format"].format(data_allocated + 1)
            elasticsearch_yml = {}
            add_common_conf(elasticsearch_yml)
            add_data_conf(elasticsearch_yml)
            elasticsearch_yml.update(
                {
                    "node.name": data_node_name,
                    "path.data": os.path.join(
                        conf["path.data"], vm_name, data_node_name
                    ),
                    "path.logs": os.path.join(
                        conf["path.logs"], vm_name, data_node_name
                    ),
                }
            )
            config_output[vm_name][data_node_name] = {
                "elasticsearch.yml": yaml.dump(elasticsearch_yml),
                "jvm.options": "\n".join(conf["data_jvm_options"]),
                "log4j2.properties": conf["log4j2.properties"],
            }
            data_allocated += 1
            conf_path = os.path.join(conf["output_path"], vm_name, data_node_name)
            cmd.append(f"ES_PATH_CONF={conf_path} bin/elasticsearch -d")
        cmd_output.append("\n".join(cmd))
        print(f"{vm_name} cmd: \n{cmd_output[-1]}\n")

    def write_file_tree(data, path):
        if not os.path.exists(path):
            os.makedirs(path)
        else:
            # remove all files in the directory
            shutil.rmtree(path)
            os.makedirs(path)

        for key, value in data.items():
            new_path = os.path.join(path, key)

            if isinstance(value, dict):
                write_file_tree(value, new_path)
            elif isinstance(value, str):
                with open(new_path, "w") as file:
                    file.write(value)

    write_file_tree(config_output, conf["output_path"])
