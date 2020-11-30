# Copyright 2015-2018 Klarna Bank AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import
import os
import copy
import json
import base64
import subprocess
import shutil
import time
from django.test import TestCase, override_settings
from django.conf import settings
from django.core import management
from django.urls import reverse
from django.contrib.auth.models import Group
from django.contrib.auth.hashers import make_password
from socrates_api.models import SocratesUser
from socrates_api.serializers import AssetSerializer
from rethinkdb import r
import uuid
import random
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse
import hmac
import hashlib

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
with open(os.path.join(BASE_DIR, 'testdata', 'intake-sample.json')) as f:
    INTAKE_DATA = json.load(f)

SOCRATES_IPAM = 'socrates_api.ipam.BonkIPAM'

@override_settings(RETHINK_DB_DB=os.environ.get('RETHINK_DB_DB', "socratesci"),
                   CELERY_TASK_EAGER_PROPAGATES=True,
                   CELERY_TASK_ALWAYS_EAGER=True,
                   CELERY_BROKER_URL='memory://',
                   SOCRATES_IPAM=SOCRATES_IPAM,
                   BONK_URL='https://localhost/bonk',
                   BONK_AUTH=('bonker', 'bonkers'),
                   BONK_SOCRATES_AUTH=('bonker', 'bonkers'),
                   ANSIBLE_PLAYBOOK_DIR=os.path.join(BASE_DIR, 'testdata', 'playbooks'),
                   SOCRATES_CHANGEFEED_MAX_WAIT=3,
                   SOCRATES_HOSTNAME_PATTERN=r'.*\.domain',
                   SOCRATES_ALIAS_PATTERN=r'.*\.domain',
                   SOCRATES_NODE_HMAC_KEY=b'secret',
)
class BaseTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super(BaseTests, cls).setUpClass()
        import socrates_api.tasks
        socrates_api.tasks.ipmi_command = lambda *args: 'Chassis Power is on'
        socrates_api.tasks.reconfigure_network_port_junos = lambda *args: True
        cls.conn = r.connect(host=settings.RETHINK_DB_HOST, port=settings.RETHINK_DB_PORT)
        try:
            r.db_drop(settings.RETHINK_DB_DB).run(cls.conn)
        except:
            pass
        r.db_create(settings.RETHINK_DB_DB).run(cls.conn)
        cls.conn.db = settings.RETHINK_DB_DB
        management.call_command('syncrethinkdb', verbosity=0)
        r.table('os').insert({'name': 'intake', 'ipxe_script': '#!ipxe', 'kickstart': ''}).run(cls.conn)

    @classmethod
    def tearDownClass(cls):
        r.db_drop(settings.RETHINK_DB_DB).run(cls.conn)
        super(BaseTests, cls).tearDownClass()

    def setUp(self):
        super(BaseTests, self).setUp()
        if SOCRATES_IPAM == 'socrates_api.ipam.BonkIPAM':
            import socrates_api.ipam
            import bonk.tasks
            class testclient_with_json(object):
                def __init__(self, response):
                    self.response = response
                def __loads(self):
                    try:
                        return json.loads(self.response.content)
                    except ValueError:
                        raise ValueError("No JSON found in: %r" % self.response.content)
                def __getattr__(self, attr):
                    if attr == 'json':
                        return self.__loads
                    else:
                        return getattr(self.response, attr)
            class requests_to_testclient(object):
                def __init__(self, testclient, **kwargs):
                    self.testclient = testclient
                    self.kwargs = kwargs
                def __getattr__(self, method):
                    def invoker(url, *args, **kwargs):
                        kwargs.update(self.kwargs)
                        if 'json' in kwargs and kwargs['json'] is not None:
                            kwargs['content_type'] = "application/json"
                            kwargs['data'] = json.dumps(kwargs['json'])
                        elif 'params' in kwargs:
                            kwargs['data'] = kwargs['params']
                        url = urlparse(url)
                        return testclient_with_json(getattr(self.testclient, method)(url.path, *args, **kwargs))
                    return invoker
            user, auth = self.create_user(settings.BONK_AUTH[0], settings.BONK_AUTH[1], is_superuser=True)
            socrates_api.ipam.requests = requests_to_testclient(self.client, HTTP_AUTHORIZATION=auth)
            bonk.tasks.requests = requests_to_testclient(self.client, HTTP_AUTHORIZATION=auth)
            response = self.client.post(reverse('bonk:vrf_list'), data=json.dumps({'vrf': 0, 'name': 'default'}), content_type="application/json", HTTP_AUTHORIZATION=auth)
            self.assertResponse(response, 201)
            response = self.client.post(reverse('bonk:block_list'), data=json.dumps({'name': 'test-block', 'vrf': 0, 'network': '10.0.0.0', 'length': 8, 'announced_by': 'socrates://localhost/firewall'}), content_type="application/json", HTTP_AUTHORIZATION=auth)
            self.assertResponse(response, 201)
            response = self.client.post(reverse('bonk:zone_list'), data=json.dumps({'type': 'internal', 'name': 'domain'}), content_type="application/json", HTTP_AUTHORIZATION=auth)
            self.assertResponse(response, 201)

    def tearDown(self):
        if SOCRATES_IPAM == 'socrates_api.ipam.BonkIPAM':
            for table in ["vrf", "ip_block", "ip_prefix", "ip_address", "dns_zone", "dns_record"]:
                r.table(table).delete().run(self.conn)
        r.table('assets').delete().run(self.conn)
        r.table('assets_raw').delete().run(self.conn)
        r.table('os').filter(r.row['name'] != 'intake').delete().run(self.conn)
        r.table('networks').delete().run(self.conn)
        r.table('quotas').delete().run(self.conn)
        r.table('events').delete().run(self.conn)
        r.table('load_balancer').delete().run(self.conn)
        super(BaseTests, self).tearDown()

    def assertResponse(self, response, status_code, body_contains=None):
        if response.status_code != status_code:
            raise self.failureException("%r != %r (body: %r)" % (response.status_code, status_code, response.content))

    def create_user(self, username='tester', password='testing', email='tester@klarna.com', **kwargs):
        user = SocratesUser.objects.create(username=username, password=make_password(password), email=email, **kwargs)
        auth = "Basic %s" % (base64.b64encode(("%s:%s" % (username, password)).encode("ascii")).decode("ascii"))
        return (user, auth)

    def create_basic_objects(self, networks=True):
        user, auth = self.create_user(is_superuser=True, is_staff=True)
        response = self.client.post('/asset/', data=json.dumps({
                'state': 'in-use',
                'version': 1,
                'asset_type': 'site',
                'service_tag': 'DC1',
                'log': 'Create site'
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)
        response = self.client.post('/asset/', data=json.dumps({
                'state': 'in-use',
                'version': 1,
                'asset_type': 'rack',
                'service_tag': 'R1',
                'log': 'Create rack'
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)
        response = self.client.post('/asset/', data=json.dumps({
                'state': 'in-use',
                'version': 1,
                'asset_type': 'network',
                'asset_subtype': 'switch',
                'parent': 'R1',
                'service_tag': 'switch',
                'url': 'ansible://localhost/switch-',
                'switch': {'domain': 'qfabric', 'port_regexp': 'Port Description TLV\\s+(?P<interface>\\S+)\\s+'},
                'log': 'Create switch'
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)
        response = self.client.post('/asset/', data=json.dumps({
                'state': 'in-use',
                'version': 1,
                'asset_type': 'network',
                'asset_subtype': 'firewall',
                'parent': 'R1',
                'service_tag': 'firewall',
                'url': 'ansible://localhost/firewall-',
                'network': {'device': 'firewall'},
                'nics': [{'name': 'nic1', 'remote': {'domain': 'qfabric', 'port': '1'}}],
                'log': 'Create firewall'
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)
        group = Group.objects.create(name='group')
        if networks:
            if SOCRATES_IPAM == 'socrates_api.ipam.BonkIPAM':
                for network in [('test', '10.0.0.0', 24), ('test2', '10.0.1.0', 24), ('installer', '10.0.93.0', 27)]:
                    response = self.client.post(reverse('bonk:prefix_list'), data=json.dumps({
                        'vrf': 0,
                        'name': network[0],
                        'network': network[1],
                        'length': network[2],
                        'state': 'allocated',
                        'permissions': {
                            'create': ['group'],
                        },
                    }), content_type="application/json", HTTP_AUTHORIZATION=auth)
                    self.assertResponse(response, 201)
                response = self.client.patch('/network/0/10.0.93.0/27', data=json.dumps({'is_installation_net': True}), content_type="application/json", HTTP_AUTHORIZATION=auth)
                self.assertResponse(response, 200)
            else:
                response = self.client.post('/network/', data=json.dumps({'domains': {'qfabric': {'name': 'test', 'vlan_id': 42}, 'firewall': {'name': 'test', 'vlan_id': 42}}, 'vrf': 0, 'network': '10.0.0.0', 'length': 24, 'permissions': {'create': ['group']}}), content_type="application/json", HTTP_AUTHORIZATION=auth)
                self.assertResponse(response, 201)
                response = self.client.post('/network/', data=json.dumps({'domains': {'qfabric': {'name': 'test2', 'vlan_id': 43}, 'firewall': {'name': 'test2', 'vlan_id': 43}}, 'vrf': 0, 'network': '10.0.1.0', 'length': 24, 'permissions': {'create': ['group']}}), content_type="application/json", HTTP_AUTHORIZATION=auth)
                self.assertResponse(response, 201)
                response = self.client.post('/network/', data=json.dumps({'domains': {'qfabric': {'name': 'installer', 'vlan_id': 44}, 'firewall': {'name': 'installer', 'vlan_id': 44}}, 'vrf': 0, 'network': '10.0.93.0', 'length': 27, 'is_installation_net': True, 'permissions': {'create': ['group']}}), content_type="application/json", HTTP_AUTHORIZATION=auth)
                self.assertResponse(response, 201)
        response = self.client.post('/os/', data=json.dumps({'name': 'centos7', 'ipxe_script': '#!ipxe\n...\n', 'kickstart': 'kick me up'}), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)
        return user, auth

    def provision_asset(self, service_tag, auth, os='centos7', owner='group', hostname='test.domain'):
        for request in INTAKE_DATA[0]:
            response = self.client.post('/intake/%s?hmac=%s&nonce=1' % (service_tag, self.make_node_hmac(service_tag, '1')), data=json.dumps(request), content_type="application/json")
            self.assertResponse(response, 200)

        response = self.client.get('/asset/%s' % service_tag, accept="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        version = json.loads(response.content)['version']
        update = {
            'version': version,
            'state': 'ready',
            'parent': None,
            'provisioning': True,
            'owner': owner,
            'log': 'Provision machine',
            'provision': {
                'os': os,
                'hostname': hostname,
                'vlan': {'cidr': '10.0.0.0/24'},
                'vlans': [{'cidr': '10.0.1.0/24', 'suffix': '-special'}],
                'storage': {
                    'os': {'by_id': '/dev/disk/by-id/....', 'controller_id': '0', 'raid': 'RAID-1', 'pdisks': [{"id": "0:1:0"}, {"id": "0:1:1"}]},
                },
            },
        }
        response = self.client.patch('/asset/%s' % service_tag, data=json.dumps(update), content_type="application/json", HTTP_AUTHORIZATION=auth)
        return response

    def make_node_hmac(self, service_tag, nonce=""):
        return hmac.HMAC(settings.SOCRATES_NODE_HMAC_KEY, (service_tag + nonce).encode("ascii"), hashlib.sha256).hexdigest()

class APITests(BaseTests):
    def test_ipxe_router_simple(self):
        response = self.client.get('/boot/TESTASS?hmac=' + self.make_node_hmac('TESTASS'))
        self.assertContains(response, "#!ipxe")

    def test_ipxe_router_provision(self):
        user, auth = self.create_basic_objects()
        response = self.client.get('/boot/TESTASS?hmac=' + self.make_node_hmac('TESTASS'))
        self.assertContains(response, "#!ipxe")

        response = self.provision_asset('TESTASS', auth, hostname='test-router.domain')
        self.assertResponse(response, 200)
        response = self.client.get('/boot/TESTASS?hmac=' + self.make_node_hmac('TESTASS'))
        self.assertContains(response, r.table("os").get_all("centos7", index="name").nth(0).run(self.conn)['ipxe_script'])

    def test_intake_report_simple_dell(self):
        response = self.client.get('/boot/TESTASS?hmac=' + self.make_node_hmac('TESTASS'))
        self.assertContains(response, "#!ipxe")

        for request in INTAKE_DATA[0]:
            response = self.client.post('/intake/TESTASS?hmac=%s&nonce=1' % self.make_node_hmac('TESTASS', '1'), data=json.dumps(request), content_type="application/json")
            self.assertResponse(response, 200)

    def test_intake_report_simple_hp(self):
        user, auth = self.create_user(is_superuser=True)
        response = self.client.post('/asset/', data=json.dumps({
                "state": "in-use",
                "asset_type": "blade-chassis",
                "version": 1,
                "service_tag": "CZ3353XCFY",
                "log": "Blade chassis"
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)

        for request in INTAKE_DATA[1]:
            response = self.client.post('/intake/TESTASS?hmac=%s&nonce=1' % self.make_node_hmac('TESTASS', '1'), data=json.dumps(request), content_type="application/json")
            self.assertResponse(response, 200)

    def test_intake_config_simple(self):
        response = self.client.get('/boot/TESTASS?hmac=' + self.make_node_hmac('TESTASS'))
        self.assertContains(response, "#!ipxe")

        response = self.client.get('/config/TESTASS?hmac=' + self.make_node_hmac('TESTASS'))
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertIn('hyperthreading', data)
        self.assertFalse(data['hyperthreading'])

    def test_kickstart_simple(self):
        response = self.client.get('/boot/TESTASS?hmac=' + self.make_node_hmac('TESTASS'))
        self.assertContains(response, "#!ipxe")
        user, auth = self.create_basic_objects()
        response = self.provision_asset('TESTASS', auth, hostname='test-kickstart-simple.domain')
        self.assertResponse(response, 200)
        response = self.client.get('/tkickstart/TESTASS')
        self.assertResponse(response, 200)
        self.assertEqual(response.content, b'kick me up')

        response = self.client.get('/tkickstartcomplete/TESTASS')
        self.assertResponse(response, 200)
        self.assertEqual(response.content, b'true')
        obj = r.table('assets').get_all('TESTASS', index='service_tag').nth(0).run(self.conn)
        self.assertEqual(obj['state'], 'in-use')
        self.assertFalse(obj['provisioning'])

    def test_asset_list(self):
        asset = AssetSerializer(None, data={'service_tag': 'TESTASS', 'state': 'new', 'asset_type': 'server', 'log': 'Created'})
        asset.is_valid(raise_exception=True)
        asset.save()

        user, auth = self.create_user(is_superuser=True)

        response = self.client.get('/asset/')
        self.assertResponse(response, 401)

        response = self.client.get('/asset/', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['service_tag'], 'TESTASS')

    def test_asset_detail(self):
        asset = AssetSerializer(None, data={'service_tag': 'TESTASS', 'state': 'new', 'asset_type': 'server', 'log': 'Created'})
        asset.is_valid(raise_exception=True)
        asset.save()

        user, auth = self.create_user(is_superuser=True)

        response = self.client.get('/asset/TESTASS')
        self.assertResponse(response, 401)

        response = self.client.get('/asset/TESTASS', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(data['service_tag'], 'TESTASS')
        self.assertEqual(data['state'], 'new')

        user2, auth2 = self.create_user(username='testing2', is_superuser=False)
        response = self.client.get('/asset/TESTASS', HTTP_AUTHORIZATION=auth2)
        self.assertResponse(response, 403)

    def test_asset_detail_no_oob_for_lusers(self):
        user, auth = self.create_basic_objects()
        response = self.provision_asset('TESTASS', auth, hostname='test-asset-no-oob.domain')

        response = self.client.get('/asset/TESTASS', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertIn('oob', data)

        user.is_superuser = False
        user.save()
        user.groups.add(Group.objects.get(name='group'))
        response = self.client.get('/asset/TESTASS', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertNotIn('oob', data)

    def test_asset_history_no_oob_for_lusers(self):
        user, auth = self.create_basic_objects()
        response = self.provision_asset('TESTASS', auth, hostname='test-asset-history-no-oob.domain')

        response = self.client.get('/asset/TESTASS', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertIn('oob', data)

        user.is_superuser = False
        user.save()
        user.groups.add(Group.objects.get(name='group'))
        response = self.client.get('/asset/TESTASS/history', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        for version in data:
            self.assertNotIn('oob', version['object'])

    def test_os_list_require_auth(self):
        response = self.client.get('/os/')
        self.assertResponse(response, 401)

    def test_os_list(self):
        user, auth = self.create_user(is_superuser=True, is_staff=True)
        response = self.client.get('/os/', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['name'], 'intake')

    def test_os_list_regular_user(self):
        user, auth = self.create_user()
        response = self.client.get('/os/', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)

    def test_os_detail(self):
        user, auth = self.create_user(is_superuser=True, is_staff=True)
        response = self.client.get('/os/osinstall', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 404)

        response = self.client.post('/os/', data=json.dumps({'name': 'osinstall', 'ipxe_script': '... schtuff'}), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)

        response = self.client.get('/os/osinstall', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(data['ipxe_script'], '... schtuff')

        response = self.client.patch('/os/osinstall', data=json.dumps({'name': 'osinstall', 'ipxe_script': '... stuff'}), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        response = self.client.get('/os/osinstall', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(data['ipxe_script'], '... stuff')

        response = self.client.delete('/os/osinstall', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 204)

    def test_health_check(self):
        response = self.client.get('/health/', HTTP_ACCEPT='application/json')
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(data, True)

    def test_network_list_unauth(self):
        response = self.client.get('/network/', HTTP_ACCEPT='application/json')
        self.assertResponse(response, 401)

    def test_network_list(self):
        user, auth = self.create_basic_objects(networks=False)
        if SOCRATES_IPAM == 'socrates_api.ipam.BonkIPAM':
            response = self.client.post(reverse('bonk:prefix_list'), data=json.dumps({
                'vrf': 0,
                'name': 'test4',
                'network': '10.0.4.0',
                'length': 24,
                'state': 'allocated',
                'permissions': {'create': ['group']},
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
            self.assertResponse(response, 201)
        else:
            response = self.client.post('/network/', data=json.dumps({'domains': {'qfabric': {'name': 'test4', 'vlan_id': 424}}, 'vrf': 0, 'network': '10.0.4.0', 'length': 24, 'permissions': {'create': ['group']}}), content_type="application/json", HTTP_AUTHORIZATION=auth)
            self.assertResponse(response, 201)

        response = self.client.get('/network/', HTTP_ACCEPT='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(data[0]['domains']['qfabric']['name'], 'test4')

        luser, lauth = self.create_user('luser', 'testing')
        group = Group.objects.get(name='group')
        response = self.client.get('/network/', HTTP_ACCEPT='application/json', HTTP_AUTHORIZATION=lauth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(data, [])

        luser.groups.add(group)
        response = self.client.get('/network/', HTTP_ACCEPT='application/json', HTTP_AUTHORIZATION=lauth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)

    def test_network_list_luser_create(self):
        luser, lauth = self.create_user('luser', 'testing')
        response = self.client.post('/network/', data=json.dumps({'domains': {'qfabric': {'name': 'test', 'vlan_id': 42}}, 'vrf': 0, 'network': '10.0.0.0', 'length': 24, 'permissions': {'write': ['testing']}}), content_type="application/json", HTTP_AUTHORIZATION=lauth)
        self.assertResponse(response, 403)

    def test_network_detail(self):
        user, auth = self.create_basic_objects()
        if SOCRATES_IPAM == 'socrates_api.ipam.BonkIPAM':
            response = self.client.post(reverse('bonk:prefix_list'), data=json.dumps({
                'vrf': 0,
                'name': 'test4',
                'network': '10.0.4.0',
                'length': 24,
                'state': 'allocated',
                'permissions': {'create': ['group']},
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
            self.assertResponse(response, 201)
        else:
            response = self.client.post('/network/', data=json.dumps({'domains': {'qfabric': {'name': 'test4', 'vlan_id': 424}}, 'vrf': 0, 'network': '10.0.4.0', 'length': 24, 'permissions': {'create': ['group']}}), content_type="application/json", HTTP_AUTHORIZATION=auth)
            self.assertResponse(response, 201)
            data = json.loads(response.content)
            self.assertIn('id', data)

        response = self.client.get('/network/0/10.0.4.0/24', HTTP_ACCEPT='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data2 = json.loads(response.content)
        self.assertEqual(data2['domains']['qfabric']['name'], 'test4')

    def test_asset_provision(self):
        user, auth = self.create_basic_objects()
        response = self.provision_asset('TESTASS', auth, hostname='test-asset-provision.domain')
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(data['service_tag'], 'TESTASS')
        response = self.client.get('/asset/TESTASS', HTTP_ACCEPT='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        asset = json.loads(response.content)
        self.assertIn('ip', asset['provision']['vlan'])

        response = self.client.delete('/asset/TESTASS', data=json.dumps({'log': 'Testing delete'}), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 204)

        response = self.client.get('/asset/TESTASS', HTTP_ACCEPT='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        asset = json.loads(response.content)
        self.assertNotIn('provision', asset)

    def test_ipam_validate(self):
        user, auth = self.create_basic_objects()

        for octet in range(1, 255):
            response = self.client.post(reverse('bonk:address_list'),
                data=json.dumps({
                    'vrf': 0,
                    'ip': '10.0.0.%d' % octet,
                    'name': 'test-ipam-validate-%d.domain' % octet,
                    'state': 'allocated',
                }), content_type="application/json", HTTP_AUTHORIZATION=auth)
            self.assertResponse(response, 201)

        response = self.provision_asset('TESTASS', auth, hostname='test-ipam-validate.domain')
        self.assertResponse(response, 400)
        self.assertIn(b'allocatable', response.content)

    def test_asset_list_as_manager(self):
        super_user, super_auth = self.create_basic_objects()

        user, auth = self.create_user(username='tester2')
        group = Group.objects.get(name='group')
        user.groups.add(group)
        response = self.provision_asset('TESTASS', super_auth, hostname='test-asset-list-as-manager.domain')
        self.assertResponse(response, 200)
        r.table('assets').filter({'service_tag': 'TESTASS'}).update({'managers': ['group']}).run(self.conn)

        response = self.client.get('/asset/', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['service_tag'], 'TESTASS')

    def disabled_test_vm_quotas(self):
        user, auth = self.create_basic_objects()
        user.groups.add(Group.objects.get(name='group'))
        Group.objects.create(name='esx-owner')
        r.table('quotas').insert({
            'group': 'group',
            'vms': 4,
            'vm_vcpus': 2,
            'total_vcpus': 4,
            'vm_ram': 8 * 1024 * 1024 * 1024,
            'total_ram': 16 * 1024 * 1024 * 1024,
            'vm_disk': 40 * 1000 * 1000 * 1000,
            'total_disk': 120 * 1000 * 1000 * 1000,
        }).run(self.conn)
        response = self.client.post('/asset/', data=json.dumps({
                "state": "in-use",
                "asset_type": "vmcluster",
                "asset_subtype": "vmware",
                "version": 1,
                "owner": "esx-owner",
                "service_tag": "ESX",
                "storage": [
                    {"datastores": {"NL": ["datastore1"]}},
                ],
                "hypervisors": [],
                "log": "cluster asset"
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)
        response = self.client.patch('/network/0/10.0.0.0/24', data=json.dumps({
                "domains": [{'domain': 'ESX', 'name': 'test'}]
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        vm = {
            "state": "ready",
            "asset_type": "vm",
            "asset_subtype": "vmware",
            "version": 1,
            "parent": "ESX",
            "owner": "group",
            "provision": {
                "os": "centos7",
                "vlan": {"domain": "qfabric", "name": "test"},
                "ram": 4 * 1024 * 1024 * 1024,
                "cpus": 1,
                "storage": {
                    "os": {
                        "by_id": "sda",
                        "size": 30000000000,
                        "class": "NL"
                    }
                }
            },
            "cpu": ["vCPU"],
            "ram": {
                "total": 4 * 1024 * 1024 * 1024,
            },
            "storage": [
                {
                    "class": "NL",
                    "filename": "/tmp/test",
                    "capacity": 30000000000,
                }
            ],
            "provisioning": True,
            "log": "Testing VM provision"
        }
        def vm_with_specifics(**fields):
            v = copy.deepcopy(vm)
            for field, value in fields.items():
                d = v
                for point in field.split("__")[:-1]:
                    d = d[point]
                d[field.split("__")[-1]] = value
            return v
        response = self.client.post('/asset/', data=json.dumps(vm_with_specifics(service_tag="socrates-test-app1", provision__hostname="socrates-test-app1.domain", provision__cpus=3)), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertContains(response, "vCPUs per VM", status_code=400)
        response = self.client.post('/asset/', data=json.dumps(vm_with_specifics(service_tag="socrates-test-app1", provision__hostname="socrates-test-app1.domain", provision__ram=9 * 1024 * 1024 * 1024)), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertContains(response, "RAM per VM", status_code=400)
        response = self.client.post('/asset/', data=json.dumps(vm_with_specifics(service_tag="socrates-test-app1", provision__hostname="socrates-test-app1.domain", provision__storage__os__size=41 * 1000 * 1000 * 1000)), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertContains(response, "disk per VM", status_code=400)
        response = self.client.post('/asset/', data=json.dumps(vm_with_specifics(service_tag="socrates-test-app1", provision__hostname="socrates-test-app1.domain", state="in-use", provisioning=False)), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)
        response = self.client.post('/asset/', data=json.dumps(vm_with_specifics(service_tag="socrates-test-app2", provision__hostname="socrates-test-app2.domain", state="in-use", provisioning=False)), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)
        response = self.client.post('/asset/', data=json.dumps(vm_with_specifics(service_tag="socrates-test-app3", provision__hostname="socrates-test-app3.domain", state="in-use", provisioning=False)), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)
        response = self.client.post('/asset/', data=json.dumps(vm_with_specifics(service_tag="socrates-test-app4", provision__hostname="socrates-test-app4.domain", provision__ram=8 * 1024 * 1024 * 1024)), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertContains(response, "exceeded your vRAM quota", status_code=400)
        response = self.client.post('/asset/', data=json.dumps(vm_with_specifics(service_tag="socrates-test-app4", provision__hostname="socrates-test-app4.domain", provision__cpus=2)), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertContains(response, "exceeded your vCPU quota", status_code=400)
        response = self.client.post('/asset/', data=json.dumps(vm_with_specifics(service_tag="socrates-test-app4", provision__hostname="socrates-test-app4.domain", provision__storage__os__size=40 * 1000 * 1000 * 1000)), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertContains(response, "exceeded your disk quota", status_code=400)
        response = self.client.post('/asset/', data=json.dumps(vm_with_specifics(service_tag="socrates-test-app4", provision__hostname="socrates-test-app4.domain", state="in-use", provisioning=False)), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)
        response = self.client.post('/asset/', data=json.dumps(vm_with_specifics(service_tag="socrates-test-app5", provision__hostname="socrates-test-app5.domain")), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertContains(response, "exceeded your VM quota of", status_code=400)

    def test_asset_actions(self):
        user, auth = self.create_basic_objects()
        response = self.provision_asset('TESTASS', auth, hostname='test-asset-actions.domain')
        self.assertResponse(response, 200)
        response = self.client.get('/tkickstartcomplete/TESTASS')
        self.assertResponse(response, 200)

        response = self.client.post('/asset/TESTASS/ipmi/', data=json.dumps({'log': 'Rebooted due to test', 'action': 'reboot'}), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)

    def test_empty_event_feed(self):
        user, auth = self.create_basic_objects()
        start_time = time.time()
        response = self.client.get('/event/feed/', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 204)
        end_time = time.time()
        self.assertAlmostEqual(int(end_time - start_time), 3, delta=1)

    def test_duplicate_key(self):
        user, auth = self.create_basic_objects()
        response = self.client.post('/os/', data=json.dumps({'name': 'centos7', 'ipxe_script': '#!ipxe\n...\n'}), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 400)
        data = json.loads(response.content)
        self.assertIn('name', data)

    def test_asset_history(self):
        user, auth = self.create_basic_objects()
        response = self.provision_asset('TESTASS', auth, hostname='test-asset-history-st.domain')

        response = self.client.get('/asset/TESTASS', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        asset = json.loads(response.content)

        response = self.client.get('/asset/%s/history' % asset['id'], HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), asset['version'])

        response = self.client.get('/asset/TESTASS/history', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), asset['version'])

    def test_network_filtering(self):
        user, auth = self.create_basic_objects()
        response = self.client.get('/network/', HTTP_ACCEPT='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 3)

        # Search for non-existing field
        response = self.client.get('/network/?is_installation_net=', HTTP_ACCEPT='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 2)

        # Search for a list field
        group = Group.objects.create(name='group2')
        response = self.client.patch('/network/%s' % data[0]['id'], data=json.dumps({'permissions': {'create': ['group', 'group2']}}), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)

        # FIXME: This test is broken right now, fix it later.
        #response = self.client.get('/network/?permissions__create=group2', HTTP_ACCEPT='application/json', HTTP_AUTHORIZATION=auth)
        #self.assertResponse(response, 200)
        #data = json.loads(response.content)
        #self.assertEqual(len(data), 1)

        # Search for a regexp
        response = self.client.get(r'/network/?network__regexp=10\.0\.1\.', HTTP_ACCEPT='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)

    def test_task_invoke(self):
        user, auth = self.create_basic_objects()
        luser, lauth = self.create_user('luser', 'testing')
        response = self.client.post(r'/task/invoke/socrates_api.tasks.cleanup_taskqueue', HTTP_AUTHORIZATION=lauth)
        self.assertResponse(response, 403)

        response = self.client.post(r'/task/invoke/socrates_api.tasks.cleanup_taskqueue', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 204)

        response = self.client.post(r'/task/invoke/socrates_api.tasks.asset_get', data=json.dumps({'args': ['switch']}), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 204)

    def test_reprovision_move_network(self):
        user, auth = self.create_basic_objects()
        response = self.provision_asset('TESTASS', auth, hostname='test-asset-reprovision-network.domain')
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(data['service_tag'], 'TESTASS')
        response = self.client.get('/tkickstartcomplete/TESTASS')
        self.assertResponse(response, 200)
        self.assertEqual(response.content, b'true')
        response = self.client.get('/asset/TESTASS', HTTP_ACCEPT='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        asset = json.loads(response.content)
        self.assertIn('ip', asset['provision']['vlan'])

        response = self.client.patch('/asset/TESTASS', data=json.dumps({
            'version': asset['version'],
            'log': 'Change network',
            'provisioning': True,
            'provision': {
                'vlan': {
                    'cidr': '10.0.1.0/24'
                },
            },
        }), content_type='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        response = self.client.get('/asset/TESTASS', HTTP_ACCEPT='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        asset2 = json.loads(response.content)
        self.assertIn('ip', asset2['provision']['vlan'])
        self.assertNotEqual(asset['provision']['vlan']['ip'], asset2['provision']['vlan']['ip'])

    def test_reprovision_change_hostname(self):
        user, auth = self.create_basic_objects()
        response = self.provision_asset('TESTASS', auth, hostname='test-asset-reprovision-hostname.domain')
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(data['service_tag'], 'TESTASS')
        response = self.client.get('/tkickstartcomplete/TESTASS')
        self.assertResponse(response, 200)
        self.assertEqual(response.content, b'true')
        response = self.client.get('/asset/TESTASS', HTTP_ACCEPT='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        asset = json.loads(response.content)
        self.assertIn('ip', asset['provision']['vlan'])

        response = self.client.patch('/asset/TESTASS', data=json.dumps({
            'version': asset['version'],
            'log': 'Change hostname',
            'provisioning': True,
            'provision': {
                'hostname': 'test-asset-reprovision-hostname2.domain'
            },
        }), content_type='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        response = self.client.get('/asset/TESTASS', HTTP_ACCEPT='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        asset2 = json.loads(response.content)
        self.assertIn('ip', asset2['provision']['vlan'])
        self.assertEqual(asset['provision']['vlan']['ip'], asset2['provision']['vlan']['ip'])
        if settings.SOCRATES_IPAM == 'socrates_api.ipam.BonkIPAM':
            response = self.client.get(reverse('bonk:address_list'), data={'name': asset2['provision']['hostname']}, HTTP_AUTHORIZATION=auth)
            data = json.loads(response.content)
            self.assertEqual(len(data), 1)
            response = self.client.get(reverse('bonk:address_list'), data={'name': asset['provision']['hostname']}, HTTP_AUTHORIZATION=auth)
            data = json.loads(response.content)
            self.assertEqual(len(data), 0)

    def test_reprovision_aliases(self):
        user, auth = self.create_basic_objects()
        response = self.provision_asset('TESTASS', auth, hostname='test-asset-reprovision-aliases.domain')
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(data['service_tag'], 'TESTASS')
        response = self.client.get('/tkickstartcomplete/TESTASS')
        self.assertResponse(response, 200)
        self.assertEqual(response.content, b'true')
        response = self.client.get('/asset/TESTASS', HTTP_ACCEPT='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        asset = json.loads(response.content)
        self.assertIn('ip', asset['provision']['vlan'])

        response = self.client.patch('/asset/TESTASS', data=json.dumps({
            'version': asset['version'],
            'log': 'Add aliases',
            'provisioning': True,
            'provision': {
                'aliases': ['test-asset-reprovision-aliases-2.domain', 'test-asset-reprovision-aliases-3.domain']
            },
        }), content_type='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        response = self.client.get('/asset/TESTASS', HTTP_ACCEPT='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        asset = json.loads(response.content)
        response = self.client.patch('/asset/TESTASS', data=json.dumps({
            'version': asset['version'],
            'log': 'Remove alias',
            'provisioning': True,
            'provision': {
                'aliases': ['test-asset-reprovision-aliases-3.domain']
            },
        }), content_type='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        if settings.SOCRATES_IPAM == 'socrates_api.ipam.BonkIPAM':
            response = self.client.get(reverse('bonk:record_list'), HTTP_AUTHORIZATION=auth)
            data = json.loads(response.content)
            self.assertEqual(len([1 for x in data if x['name'] == 'test-asset-reprovision-aliases-3.domain']), 1)
            self.assertEqual(len([1 for x in data if x['name'] == 'test-asset-reprovision-aliases-2.domain']), 0)

    def test_reprovision_no_dns_change(self):
        user, auth = self.create_basic_objects()
        response = self.provision_asset('TESTASS', auth, hostname='test-asset-reprovision-nodns.domain')
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(data['service_tag'], 'TESTASS')
        response = self.client.get('/tkickstartcomplete/TESTASS')
        self.assertResponse(response, 200)
        self.assertEqual(response.content, b'true')
        response = self.client.get('/asset/TESTASS', HTTP_ACCEPT='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        asset = json.loads(response.content)
        self.assertIn('ip', asset['provision']['vlan'])

        response = self.client.patch('/asset/TESTASS', data=json.dumps({
            'version': asset['version'],
            'log': 'Change non-DNS',
            'provisioning': True,
            'provision': {
                'storage': {
                    'os': {'by_id': '/dev/disk/by-id/qwer'},
                },
            },
        }), content_type='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        response = self.client.get('/asset/TESTASS', HTTP_ACCEPT='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        asset2 = json.loads(response.content)
        self.assertIn('ip', asset2['provision']['vlan'])
        self.assertEqual(asset['provision']['vlan']['ip'], asset2['provision']['vlan']['ip'])

    def test_network_collect(self):
        try:
            os.unlink(os.path.join(BASE_DIR, 'testdata', 'firewall.picker'))
        except:
            pass
        try:
            os.unlink(os.path.join(BASE_DIR, 'testdata', 'switch.picker'))
        except:
            pass
        user, auth = self.create_basic_objects()
        response = self.client.post(r'/task/invoke/socrates_api.tasks.collect_networks', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 204)

    def test_asset_reviews(self):
        user, auth = self.create_basic_objects()
        response = self.provision_asset('TESTASS', auth, hostname='test-asset-reviews.domain')
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(data['service_tag'], 'TESTASS')
        response = self.client.get('/tkickstartcomplete/TESTASS')
        self.assertResponse(response, 200)
        response = self.client.get('/asset/TESTASS', HTTP_ACCEPT='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        asset = json.loads(response.content)
        self.assertIn('ip', asset['provision']['vlan'])

        response = self.client.patch('/asset/TESTASS', data=json.dumps({'log': 'Enable reviews', 'version': asset['version'], 'needs_review': True}), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        asset = json.loads(response.content)

        response = self.client.delete('/asset/TESTASS', data=json.dumps({'log': 'Testing delete'}), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 400)

        self.assertEqual(r.table("reviews").count().run(self.conn), 0)

        user2, auth2 = self.create_user(username='testing2', is_superuser=False)
        group2 = Group.objects.create(name='group2')
        user2.groups.add(Group.objects.get(name=asset['owner']))
        user2.groups.add(group2)

        response = self.client.patch('/asset/TESTASS', data=json.dumps({'log': 'New manager', 'version': asset['version'], 'managers': ['group2']}), content_type="application/json", HTTP_AUTHORIZATION=auth2)
        self.assertResponse(response, 202)

        response = self.client.get('/review/', HTTP_AUTHORIZATION=auth2)
        self.assertResponse(response, 200)
        reviews = json.loads(response.content)
        self.assertEqual(len(reviews), 1)
        self.assertEqual(reviews[0]['state'], 'pending')
        self.assertEqual(reviews[0]['submitter'], user2.username)
        self.assertEqual(reviews[0]['reviewers'], [asset['owner']])
        self.assertEqual(reviews[0]['object_id'], asset['id'])
        self.assertEqual(reviews[0]['is_partial'], True)
        self.assertEqual(reviews[0]['approvals'], [])

        response = self.client.patch('/review/%s' % reviews[0]['id'], data=json.dumps({'approvals': [user.username]}), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        review = json.loads(response.content)
        self.assertEqual(review['state'], 'approved')

        response = self.client.patch('/review/%s' % reviews[0]['id'], data=json.dumps({'state': 'executed'}), content_type="application/json", HTTP_AUTHORIZATION=auth2)
        self.assertResponse(response, 200)

        response = self.client.get('/asset/TESTASS', HTTP_ACCEPT='application/json', HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        asset = json.loads(response.content)
        self.assertEqual(asset['managers'], ['group2'])

    def create_lb_objects(self, auth):
        response = self.client.post('/asset/', data=json.dumps({
                'state': 'in-use',
                'version': 1,
                'asset_type': 'network',
                'asset_subtype': 'loadbalancer',
                'service_tag': 'lb1',
                'url': 'ansible://lb-testing-app1.domain/lb-',
                'log': 'Create load balancer'
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)
        response = self.client.post('/asset/', data=json.dumps({
                'state': 'in-use',
                'version': 1,
                'asset_type': 'lbcluster',
                'service_tag': 'lbcluster',
                'composed_of': ['lb1'],
                'log': 'Create load balancer cluster'
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)

    def test_load_balancer_irule(self):
        user, auth = self.create_basic_objects()
        self.create_lb_objects(auth)
        luser, lauth = self.create_user('luser', 'testing')
        group = Group.objects.get(name='group')
        luser.groups.add(group)

        response = self.client.get(reverse('socrates_api:loadbalancer_irule_list'),
            HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(data, [])

        response = self.client.post(reverse('socrates_api:loadbalancer_irule_list'), data=json.dumps({
                'name': "irule1",
                'code': 'return false',
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)

        response = self.client.get(reverse('socrates_api:loadbalancer_irule_list'),
            HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['name'], 'irule1')

        response = self.client.get(reverse('socrates_api:loadbalancer_irule_list'),
            HTTP_AUTHORIZATION=lauth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(data, [])

        for a, c in [(lauth, 403), (auth, 200), (lauth, 200)]:
            response = self.client.patch(reverse('socrates_api:loadbalancer_irule_detail',
                    kwargs={'slug': 'irule1'}),
                data=json.dumps({
                    'permissions': {
                        'write': ['group'],
                    },
                }), content_type="application/json", HTTP_AUTHORIZATION=a)
            self.assertResponse(response, c)

        response = self.client.get(reverse('socrates_api:loadbalancer_irule_list'),
            HTTP_AUTHORIZATION=lauth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['name'], 'irule1')

    def test_load_balancer(self):
        user, auth = self.create_basic_objects()
        self.create_lb_objects(auth)
        luser, lauth = self.create_user('luser', 'testing')
        group = Group.objects.get(name='group')
        luser.groups.add(group)

        response = self.client.get(reverse('socrates_api:loadbalancer_list'),
            HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(data, [])

        if SOCRATES_IPAM == 'socrates_api.ipam.BonkIPAM':
            response = self.client.post(reverse('bonk:prefix_allocate', kwargs={
                        'vrf': 0,
                        'network': '10.0.0.0',
                        'length': 24,
                    }),
                data=json.dumps({
                    'name': 'lb-service1.domain',
                }), content_type="application/json", HTTP_AUTHORIZATION=auth)
            self.assertResponse(response, 201)
            ip1 = json.loads(response.content)['ip']

        response = self.client.post(reverse('socrates_api:loadbalancer_list'), data=json.dumps({
                'cluster': 'lbcluster',
                'name': "service1",
                'members': [{'name': 'lb-server1.domain', 'port': 443}],
                'ip': ip1,
                'protocol': 'tcp',
                'port': 443,
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)

        response = self.client.get(reverse('socrates_api:loadbalancer_list'),
            HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['name'], 'service1')

        response = self.client.get(reverse('socrates_api:loadbalancer_list'),
            HTTP_AUTHORIZATION=lauth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(data, [])

        for a, c in [(lauth, 403), (auth, 200), (lauth, 200)]:
            response = self.client.patch(reverse('socrates_api:loadbalancer_detail',
                    kwargs={'slug': 'service1'}),
                data=json.dumps({
                    'permissions': {
                        'write': ['group'],
                    },
                }), content_type="application/json", HTTP_AUTHORIZATION=a)
            self.assertResponse(response, c)

        response = self.client.get(reverse('socrates_api:loadbalancer_list'),
            HTTP_AUTHORIZATION=lauth)
        self.assertResponse(response, 200)
        data = json.loads(response.content)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['name'], 'service1')

        response = self.client.delete(reverse('socrates_api:loadbalancer_detail',
                kwargs={'slug': 'service1'}), HTTP_AUTHORIZATION=lauth)
        self.assertResponse(response, 204)

    def test_load_balancer_uniqueness(self):
        user, auth = self.create_basic_objects()
        self.create_lb_objects(auth)
        luser, lauth = self.create_user('luser', 'testing')
        group = Group.objects.get(name='group')
        luser.groups.add(group)

        if SOCRATES_IPAM == 'socrates_api.ipam.BonkIPAM':
            response = self.client.post(reverse('bonk:prefix_allocate', kwargs={
                        'vrf': 0,
                        'network': '10.0.0.0',
                        'length': 24,
                    }),
                data=json.dumps({
                    'name': 'lb-service1.domain',
                }), content_type="application/json", HTTP_AUTHORIZATION=auth)
            self.assertResponse(response, 201)
            ip1 = json.loads(response.content)['ip']
            response = self.client.post(reverse('bonk:prefix_allocate', kwargs={
                        'vrf': 0,
                        'network': '10.0.0.0',
                        'length': 24,
                    }),
                data=json.dumps({
                    'name': 'lb-service2.domain',
                }), content_type="application/json", HTTP_AUTHORIZATION=auth)
            self.assertResponse(response, 201)
            ip2 = json.loads(response.content)['ip']

        response = self.client.post(reverse('socrates_api:loadbalancer_list'), data=json.dumps({
                'cluster': 'lbcluster',
                'name': "service1",
                'members': [{'name': 'lb-server1.domain', 'port': 443}],
                'ip': ip1,
                'protocol': 'tcp',
                'port': 443,
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)

        response = self.client.post(reverse('socrates_api:loadbalancer_list'), data=json.dumps({
                'cluster': 'lbcluster',
                'name': "service2",
                'members': [{'name': 'lb-server1.domain', 'port': 443}],
                'ip': ip1,
                'protocol': 'tcp',
                'port': 443,
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 400)

        response = self.client.post(reverse('socrates_api:loadbalancer_list'), data=json.dumps({
                'cluster': 'lbcluster',
                'name': "service2",
                'members': [{'name': 'lb-server1.domain', 'port': 443}],
                'ip': ip2,
                'protocol': 'http',
                'port': 443,
                'endpoints': ['https://lb-target.domain/path'],
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)

        response = self.client.post(reverse('socrates_api:loadbalancer_list'), data=json.dumps({
                'cluster': 'lbcluster',
                'name': "service3",
                'members': [{'name': 'lb-server1.domain', 'port': 443}],
                'ip': ip2,
                'protocol': 'http',
                'port': 443,
                'endpoints': ['https://lb-target.domain/path2'],
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)

        response = self.client.post(reverse('socrates_api:loadbalancer_list'), data=json.dumps({
                'cluster': 'lbcluster',
                'name': "service4",
                'members': [{'name': 'lb-server1.domain', 'port': 443}],
                'ip': ip2,
                'protocol': 'http',
                'port': 443,
                'endpoints': ['https://lb-target.domain/path2'],
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 400)

    def test_load_balancer_wildcard(self):
        user, auth = self.create_basic_objects()
        self.create_lb_objects(auth)
        luser, lauth = self.create_user('luser', 'testing')
        group = Group.objects.get(name='group')
        luser.groups.add(group)

        if SOCRATES_IPAM == 'socrates_api.ipam.BonkIPAM':
            response = self.client.post(reverse('bonk:prefix_allocate', kwargs={
                        'vrf': 0,
                        'network': '10.0.0.0',
                        'length': 24,
                    }),
                data=json.dumps({
                    'name': 'lb-service1.domain',
                }), content_type="application/json", HTTP_AUTHORIZATION=auth)
            self.assertResponse(response, 201)
            ip1 = json.loads(response.content)['ip']
            response = self.client.post(reverse('bonk:prefix_allocate', kwargs={
                        'vrf': 0,
                        'network': '10.0.0.0',
                        'length': 24,
                    }),
                data=json.dumps({
                    'name': 'lb-service2.domain',
                }), content_type="application/json", HTTP_AUTHORIZATION=auth)
            self.assertResponse(response, 201)
            ip2 = json.loads(response.content)['ip']

        response = self.client.post(reverse('socrates_api:loadbalancer_list'), data=json.dumps({
                'cluster': 'lbcluster',
                'name': "service5",
                'members': [{'name': 'lb-server1.domain', 'port': 443}],
                'protocol': 'http',
                'endpoints': ['http://*.lb-target.domain/'],
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)

    def test_firewall_ruleset(self):
        user, auth = self.create_basic_objects()

        response = self.client.post(reverse('socrates_api:firewall_addressgroup_list'), data=json.dumps({
                'name': 'testgroup',
                'addresses': [
                    {'vrf': 0, 'address': '10.0.0.4', 'length': 32},
                ]
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)

        response = self.client.patch(reverse('socrates_api:firewall_addressgroup_detail', kwargs={'slug': 'testgroup'}), data=json.dumps({
                'addresses': [
                    {'vrf': 0, 'address': '10.0.0.4', 'length': 32},
                    {'vrf': 0, 'address': '10.0.0.5', 'length': 32},
                ]
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)

        response = self.client.post(reverse('socrates_api:firewall_ruleset_list'), data=json.dumps({
                'name': 'ruleset1',
                'rules': [
                    {
                        'type': 'egress',
                        'protocol': 'tcp',
                        'destination_addresses': [
                            {'vrf': 0, 'address': '10.0.0.2', 'length': 32},
                            {'vrf': 0, 'address': '10.0.0.3', 'length': 32},
                            {'vrf': 0, 'address': '10.0.1.2', 'length': 32},
                        ],
                        'destination_ports': [443],
                    },
                ]
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)

        response = self.client.post(reverse('socrates_api:firewall_ruleset_list'), data=json.dumps({
                'name': 'ruleset2',
                'rulesets': ['ruleset1'],
                'rules': [
                    {
                        'type': 'ingress',
                        'protocol': 'tcp',
                        'source_addresses': [
                            {'vrf': 0, 'address': '10.0.0.0', 'length': 8},
                        ],
                        'destination_ports': [443],
                    },
                    {
                        'type': 'egress',
                        'protocol': 'tcp',
                        'destination_addresses': [
                            {'address_group': 'testgroup'},
                            {'vrf': 0, 'address': '10.0.1.12', 'length': 32},
                            {'vrf': 0, 'address': '10.0.1.13', 'length': 32},
                        ],
                        'destination_ports': [443],
                    },
                ]
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)

        response = self.client.post(reverse('socrates_api:firewall_ruleset_list'), data=json.dumps({
                'name': 'ruleset_range1',
                'rules': [
                    {
                        'type': 'ingress',
                        'protocol': 'tcp',
                        'source_addresses': [
                            {'vrf': 0, 'address': '10.0.0.0', 'length': 8},
                        ],
                        'destination_ports': [{'start': 9000, 'end': 9090}],
                    },
                    {
                        'type': 'egress',
                        'protocol': 'tcp',
                        'destination_addresses': [
                            {'address_group': 'testgroup'},
                            {'vrf': 0, 'address': '10.0.1.12', 'length': 32},
                            {'vrf': 0, 'address': '10.0.1.13', 'length': 32},
                        ],
                        'destination_ports': [443],
                    },
                ]
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 201)

        response = self.client.post(reverse('socrates_api:firewall_ruleset_list'), data=json.dumps({
                'name': 'ruleset_faulty1',
                'rules': [
                    {
                        'type': 'ingress',
                        'protocol': 'tcp',
                        'source_addresses': [
                            {'vrf': 0, 'address': '10.0.0.0', 'length': 8},
                        ],
                        'destination_ports': [{'start': 8080, 'end': '8090'}],
                    },
                    {
                        'type': 'egress',
                        'protocol': 'tcp',
                        'destination_addresses': [
                            {'address_group': 'testgroup'},
                            {'vrf': 0, 'address': '10.0.1.12', 'length': 32},
                        ],
                        'destination_ports': [443],
                    },
                ]
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 400)

        response = self.client.post(reverse('socrates_api:firewall_ruleset_list'), data=json.dumps({
                'name': 'ruleset_faulty2',
                'rules': [
                    {
                        'type': 'ingress',
                        'protocol': 'tcp',
                        'source_addresses': [
                            {'vrf': 0, 'address': '10.0.0.0', 'length': 8},
                        ],
                        'destination_ports': [{'start': 8443}],
                    },
                    {
                        'type': 'egress',
                        'protocol': 'tcp',
                        'destination_addresses': [
                            {'address_group': 'testgroup'},
                            {'vrf': 0, 'address': '10.0.1.12', 'length': 32},
                        ],
                        'destination_ports': [443],
                    },
                ]
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 400)

        response = self.client.post(reverse('socrates_api:firewall_ruleset_list'), data=json.dumps({
                'name': 'ruleset_faulty3',
                'rules': [
                    {
                        'type': 'ingress',
                        'protocol': 'tcp',
                        'source_addresses': [
                            {'vrf': 0, 'address': '10.0.0.0', 'length': 8},
                        ],
                        'destination_ports': [{'start': 41000, 'end': 40000}],
                    },
                    {
                        'type': 'egress',
                        'protocol': 'tcp',
                        'destination_addresses': [
                            {'address_group': 'testgroup'},
                            {'vrf': 0, 'address': '10.0.1.12', 'length': 32},
                        ],
                        'destination_ports': [443],
                    },
                ]
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 400)

        response = self.client.patch(reverse('socrates_api:network_detail', kwargs={
                'vrf': 0, 'network': '10.0.0.0', 'length': 24
            }), data=json.dumps({
                'ruleset': 'ruleset2'
            }), content_type="application/json", HTTP_AUTHORIZATION=auth)
        self.assertResponse(response, 200)
