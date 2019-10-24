import mock

from mozdef_util.utilities.toUTC import toUTC

from mq.plugins.guardDuty import message


class TestGuardDuty(object):
    def setup(self):
        self.plugin = message()
        self.metadata = {"index": "events"}

    # Should never match and be modified by the plugin
    def test_nosource_log(self):
        metadata = {"index": "events"}
        event = {"tags": "guardduty"}
        event["details"] = []

        result, metadata = self.plugin.onMessage(event, metadata)
        # in = out - plugin didn't touch it
        assert result == event

    # Should never match and be modified by the plugin
    def test_wrongsource_log(self):
        metadata = {"index": "events"}
        event = {"tags": "guardduty", "source": "stackdriver"}
        event["details"] = []

        result, metadata = self.plugin.onMessage(event, metadata)
        # in = out - plugin didn't touch it
        assert result == event

    # Should never match and be modified by the plugin
    def test_nodetails_log(self):
        metadata = {"index": "events"}
        event = {"key1": "syslog", "source": "guardduty"}

        result, metadata = self.plugin.onMessage(event, metadata)
        # in = out - plugin didn't touch it
        assert result == event

    # @mock.patch("mq.plugins.guardDuty.node")
    # def test_mozdefhostname_mock_string(self, mock_path):
    #    mock_path.return_value = "samplehostname"
    #    event = {"tags": ["pubsub"]}
    #    event = {
    #        "tags": ["pubsub"],
    #        "receivedtimestamp": "2019-09-25T23:51:33.962907335Z",
    #        "mozdefhostname": "samplehostname",
    #    }
    #    event["details"] = {
    #        "logName": "projects/mcd-001-252615/logs/cloudaudit.googleapis.com%2Fdata_access",
    #        "protoPayload": {"@type": "type.googleapis.com/google.cloud.audit.AuditLog"},
    #        "timestamp": "2019-09-25T23:51:33.962907335Z",
    #        "utctimestamp": "2019-09-25T23:51:33.962907335Z",
    #    }
    #    plugin = message()
    #    result, metadata = plugin.onMessage(event, self.metadata)
    #    assert result["mozdefhostname"] == "samplehostname"

    def verify_metadata(self, metadata):
        assert metadata["index"] == "events"

    def verify_defaults(self, result):
        assert result["source"] == "guardduty"
        assert result["customendpoint"] == ""
        assert toUTC(result["receivedtimestamp"]).isoformat() == result["receivedtimestamp"]

    def test_defaults(self):
        event = {'receivedtimestamp': '2019-08-21T21:01:11.288139+00:00', 'mozdefhostname': 'mozdefqa2.private.mdc1.mozilla.com', 'tags': ['gd2md-GuardDutyEventNormalization-5HTB8BEL5Y1Q-SqsOutput-1D5MQWALTYJ8P'], 'severity': 'INFO', 'details': {'severity': 2, 'tags': ['PORT_PROBE'], 'schemaversion': '2.0', 'accountid': '692406183521', 'region': 'us-west-2', 'partition': 'aws', 'id': '96b65ab53d3c18c0b145814c2f8c7673', 'arn': 'arn:aws:guardduty:us-west-2:692406183521:detector/90b4e5d7bef5a2adc076a62bd3d88c78/finding/96b65ab53d3c18c0b145814c2f8c7673', 'type': 'Recon:EC2/PortProbeUnprotectedPort', 'resource': {'resourcetype': 'Instance', 'instancedetails': {'instanceid': 'i-00c19ca3bf7d2e7db', 'instancetype': 'c3.xlarge', 'launchtime': '2019-08-21T17:42:09Z', 'platform': None, 'productcodes': [], 'iaminstanceprofile': None, 'networkinterfaces': [{'ipv6addresses': [], 'networkinterfaceid': 'eni-0133432eb01499238', 'privatednsname': 'ip-10-144-29-94.us-west-2.compute.internal', 'privateipaddress': '10.144.29.94', 'privateipaddresses': [{'privatednsname': 'ip-10-144-29-94.us-west-2.compute.internal', 'privateipaddress': '10.144.29.94'}], 'subnetid': 'subnet-d948b6bf', 'vpcid': 'vpc-35df7053', 'securitygroups': [{'groupname': 'docker-worker - gecko-workers', 'groupid': 'sg-2728435d'}], 'publicdnsname': 'ec2-54-218-76-206.us-west-2.compute.amazonaws.com', 'publicip': '54.218.76.206'}], 'tags': [{'key': 'Name', 'value': 'gecko-t-linux-xlarge'}, {'key': 'WorkerType', 'value': 'ec2-manager-production/gecko-t-linux-xlarge'}, {'key': 'Owner', 'value': 'ec2-manager-production'}], 'instancestate': 'running', 'availabilityzone': 'us-west-2a', 'imageid': 'ami-0f4a83b0dd042b564', 'imagedescription': 'null'}}, 'createdat': '2019-08-21T18:22:30.008Z', 'updatedat': '2019-08-21T20:44:48.673Z', 'title': 'Unprotected port on EC2 instance i-00c19ca3bf7d2e7db is being probed.', 'description': 'EC2 instance has an unprotected port which is being probed by a known malicious host.', 'finding': {'servicename': 'guardduty', 'detectorid': '90b4e5d7bef5a2adc076a62bd3d88c78', 'action': {'actiontype': 'PORT_PROBE', 'portprobeaction': {'portprobedetails': [{'localportdetails': {'port': 33895, 'portname': 'Unknown'}, 'remoteipdetails': {'ipaddressv4': '81.22.45.239', 'organization': {'asn': '49505', 'asnorg': 'OOO Network of data-centers Selectel', 'isp': 'Infolink LLC', 'org': 'Infolink LLC'}, 'country': {'countryname': 'Russia'}, 'city': {'cityname': ''}, 'geolocation': {'lat': 55.7386, 'lon': 37.6068}}}, {'localportdetails': {'port': 33201, 'portname': 'Unknown'}, 'remoteipdetails': {'ipaddressv4': '185.176.27.42', 'organization': {'asn': '204428', 'asnorg': 'SS-Net', 'isp': 'IP Khnykin Vitaliy Yakovlevich', 'org': 'IP Khnykin Vitaliy Yakovlevich'}, 'country': {'countryname': 'Russia'}, 'city': {'cityname': ''}, 'geolocation': {'lat': 55.7386, 'lon': 37.6068}}}, {'localportdetails': {'port': 33089, 'portname': 'Unknown'}, 'remoteipdetails': {'ipaddressv4': '92.63.194.74', 'organization': {'asn': '48817', 'asnorg': 'Chelyshev Sergej Aleksandrovich', 'isp': 'OOO Patent-Media', 'org': 'OOO Patent-Media'}, 'country': {'countryname': 'Ukraine'}, 'city': {'cityname': ''}, 'geolocation': {'lat': 50.45, 'lon': 30.5233}}}], 'blocked': False}}, 'resourcerole': 'TARGET', 'additionalinfo': {'threatname': 'Scanner', 'threatlistname': 'ProofPoint'}, 'evidence': {'threatintelligencedetails': [{'threatnames': ['Scanner'], 'threatlistname': 'ProofPoint'}]}, 'eventfirstseen': '2019-08-21T18:06:13Z', 'eventlastseen': '2019-08-21T20:34:12Z', 'archived': False, 'count': 3}}, 'timestamp': '2019-08-21T21:01:09.004000+00:00', 'utctimestamp': '2019-08-21T21:01:09.004000+00:00', 'hostname': 'i-00c19ca3bf7d2e7db', 'processname': 'guardduty', 'processid': '1337', 'summary': 'EC2 instance has an unprotected port which is being probed by a known malicious host.', 'category': 'Recon:EC2/PortProbeUnprotectedPort', 'type': 'event', 'source': 'guardduty'}
        result, metadata = self.plugin.onMessage(event, self.metadata)
        self.verify_defaults(result)
        self.verify_metadata(metadata)
        # assert result["category"] == "data_access"

    def test_nomatch_syslog(self):
        event = {
            "category": "syslog",
            "processid": "0",
            "receivedtimestamp": "2017-09-26T00:22:24.210945+00:00",
            "severity": "7",
            "utctimestamp": "2017-09-26T00:22:23+00:00",
            "timestamp": "2017-09-26T00:22:23+00:00",
            "hostname": "something1.test.com",
            "mozdefhostname": "something1.test.com",
            "summary": "Connection from 10.22.74.208 port 9071 on 10.22.74.45 pubsub stackdriver port 22\n",
            "eventsource": "systemslogs",
            "tags": "something",
            "details": {
                "processid": "21233",
                "sourceipv4address": "10.22.74.208",
                "hostname": "hostname1.subdomain.domain.com",
                "program": "sshd",
                "sourceipaddress": "10.22.74.208",
            },
        }
        result, metadata = self.plugin.onMessage(event, self.metadata)
        assert result["category"] == "syslog"
        assert result["eventsource"] == "systemslogs"
        assert result == event

    def test_nomatch_auditd(self):
        event = {
            "category": "execve",
            "processid": "0",
            "receivedtimestamp": "2017-09-26T00:36:27.463745+00:00",
            "severity": "INFO",
            "utctimestamp": "2017-09-26T00:36:27+00:00",
            "tags": ["audisp-json", "2.1.1", "audit"],
            "summary": "Execve: sh -c sudo squid proxy /usr/lib64/nagios/plugins/custom/check_auditd.sh",
            "processname": "audisp-json",
            "details": {
                "fsuid": "398",
                "tty": "(none)",
                "uid": "398",
                "process": "/bin/bash",
                "auditkey": "exec",
                "pid": "10553",
                "processname": "sh",
                "session": "16467",
                "fsgid": "398",
                "sgid": "398",
                "auditserial": "3834716",
                "inode": "1835094",
                "ouid": "0",
                "ogid": "0",
                "suid": "398",
                "originaluid": "0",
                "gid": "398",
                "originaluser": "pubsub",
                "ppid": "10552",
                "cwd": "/",
                "parentprocess": "stackdriver",
                "euid": "398",
                "path": "/bin/sh",
                "rdev": "00:00",
                "dev": "08:03",
                "egid": "398",
                "command": "sh -c sudo /usr/lib64/nagios/plugins/custom/check_auditd.sh",
                "mode": "0100755",
                "user": "squid",
            },
        }
        result, metadata = self.plugin.onMessage(event, self.metadata)
        assert result["category"] == "execve"
        assert "eventsource" not in result
        assert result == event
