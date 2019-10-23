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
        event = {
            'receivedtimestamp': '2019-10-05T00:26:33.552193+00:00',
            "timestamp": "2019-10-05T00:26:33.552193+00:00",
            "utctimestamp": "2019-10-05T00:26:33.552193+00:00",
            'mozdefhostname': 'mbp.local',
            'tags': ['gd2md-GuardDutyEventNormalization-5HTB8BEL5Y1Q-SqsOutput-1D5MQWALTYJ8P'],
            'severity': 'INFO',
            'source': 'guardduty',
            'details': {
                'timestamp': '2019-10-05 00:26:32.995000',
                'hostname': 'i-02688b720cb4250c6',
                'processname': 'guardduty',
                'processid': 1337,
                'severity': 'INFO',
                'summary': 'EC2 instance has an unprotected port which is being probed by a known malicious host.',
                'category': 'Recon:EC2/PortProbeUnprotectedPort',
                'source': 'guardduty',
                'tags': ['PORT_PROBE'],
                'schemaVersion': '2.0',
                'accountId': '692406183521',
                'region': 'us-west-2',
                'partition': 'aws',
                'id': '7eb6cca4f0a7bae51a28c70dc691daf2',
                'arn': 'arn:aws:guardduty:us-west-2:692406183521:detector/90b4e5d7bef5a2adc076a62bd3d88c78/finding/7eb6cca4f0a7bae51a28c70dc691daf2',
                'type': 'Recon:EC2/PortProbeUnprotectedPort',
                'resource': {
                    'resourceType': 'Instance',
                    'instanceDetails': {
                        'instanceId': 'i-02688b720cb4250c6',
                        'instanceType': 'm3.xlarge',
                        'launchTime': '2019-10-04T21:59:00Z',
                        'platform': None,
                        'productCodes': [],
                        'iamInstanceProfile': None,
                        'networkInterfaces': [
                            {
                                'ipv6Addresses': [],
                                'networkInterfaceId': 'eni-0248a175fb20360d9',
                                'privateDnsName': 'ip-10-144-54-71.us-west-2.compute.internal',
                                'privateIpAddress': '10.144.54.71',
                                'privateIpAddresses': [
                                    {
                                        'privateDnsName': 'ip-10-144-54-71.us-west-2.compute.internal',
                                        'privateIpAddress': '10.144.54.71',
                                    }
                                ],
                                'subnetId': 'subnet-540a9f0f',
                                'vpcId': 'vpc-35df7053',
                                'securityGroups': [
                                    {'groupName': 'docker-worker - gecko-workers', 'groupId': 'sg-2728435d'}
                                ],
                                'publicDnsName': 'ec2-34-219-172-44.us-west-2.compute.amazonaws.com',
                                'publicIp': '34.219.172.44',
                            }
                        ],
                        'tags': [
                            {'key': 'WorkerType', 'value': 'ec2-manager-production/gecko-t-linux-xlarge'},
                            {'key': 'Name', 'value': 'gecko-t-linux-xlarge'},
                            {'key': 'Owner', 'value': 'ec2-manager-production'},
                        ],
                        'instanceState': 'running',
                        'availabilityZone': 'us-west-2c',
                        'imageId': 'ami-0a6d90c9d398491a3',
                        'imageDescription': 'null',
                    },
                },
                'severity': 2,
                'createdAt': '2019-10-05T00:20:18.895Z',
                'updatedAt': '2019-10-05T00:20:18.895Z',
                'title': 'Unprotected port on EC2 instance i-02688b720cb4250c6 is being probed.',
                'description': 'EC2 instance has an unprotected port which is being probed by a known malicious host.',
                'finding': {
                    'serviceName': 'guardduty',
                    'detectorId': '90b4e5d7bef5a2adc076a62bd3d88c78',
                    'action': {
                        'actionType': 'PORT_PROBE',
                        'portProbeAction': {
                            'portProbeDetails': [
                                {
                                    'localPortDetails': {'port': 47808, 'portName': 'Unknown'},
                                    'remoteIpDetails': {
                                        'ipAddressV4': '198.108.67.133',
                                        'organization': {
                                            'asn': '237',
                                            'asnOrg': 'Merit Network Inc.',
                                            'isp': 'Merit Network',
                                            'org': 'Merit Network',
                                        },
                                        'country': {'countryName': 'United States'},
                                        'city': {'cityName': ''},
                                        'geoLocation': {'lat': 37.751, 'lon': -97.822},
                                    },
                                }
                            ],
                            'blocked': False,
                        },
                    },
                    'resourceRole': 'TARGET',
                    'additionalInfo': {'threatName': 'Scanner', 'threatListName': 'ProofPoint'},
                    'evidence': {
                        'threatIntelligenceDetails': [{'threatListName': 'ProofPoint', 'threatNames': ['Scanner']}]
                    },
                    'eventFirstSeen': '2019-10-04T23:29:50Z',
                    'eventLastSeen': '2019-10-04T23:30:44Z',
                    'archived': False,
                    'count': 1,
                },
            },
        }
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
