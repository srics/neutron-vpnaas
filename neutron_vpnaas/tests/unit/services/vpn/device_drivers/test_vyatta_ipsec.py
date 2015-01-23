import mock

from neutron.openstack.common import uuidutils
from neutron_vpnaas.services.vpn.device_drivers import vyatta_ipsec
from neutron_vpnaas.tests import base

_uuid = uuidutils.generate_uuid

FAKE_HOST = 'fake_host'

FAKE_VROUTER_CONFIG = """
vpn {
    ipsec {
        esp-group esp0-4cdd1259f3b543709dd6a98b5906d8d5 {
            compression disable
            lifetime 3600
            mode tunnel
            pfs dh-group5
            proposal 1 {
                encryption aes128
                hash sha1
            }
        }
        ike-group ike0-5e152b0389484e7da0d947a0dcc9d67c {
            dead-peer-detection {
                action hold
                interval 30
                timeout 120
            }
            lifetime 3600
            proposal 1 {
                encryption aes128
                hash sha1
            }
        }
        ipsec-interfaces {
            interface eth1
        }
        site-to-site {
            peer 172.24.4.234 {
                authentication {
                    mode pre-shared-secret
                    pre-shared-secret ****************
                }
                connection-type initiate
                default-esp-group esp0-4cdd1259f3b543709dd6a98b5906d8d5
                description os-id:5400a3ac3ac94b6d8a359f1edac263f2:8353900308524e68a2f8bd91d92449fa
                ike-group ike0-5e152b0389484e7da0d947a0dcc9d67c
                local-address 172.24.4.2
                tunnel 0 {
                    allow-nat-networks disable
                    allow-public-networks enable
                    local {
                        prefix 10.0.0.0/24
                    }
                    remote {
                        prefix 10.2.0.0/24
                    }
                }
            }
        }
    }
}
"""


class FakeVRouterClient(object):

    def get_vrouter_configuration(self):
        return FAKE_VROUTER_CONFIG


def fake_vrouter_factory(router_id):
    return FakeVRouterClient()


class TestVyattaDeviceDriver(base.BaseTestCase):

    def setUp(self, driver=vyatta_ipsec.VyattaIPSecDriver):
        super(TestVyattaDeviceDriver, self).setUp()

        self.agent = mock.Mock()
        self.driver = driver(self.agent, FAKE_HOST)
        self.driver.server_api = mock.Mock()
        self.driver._svc_delete = mock.Mock()
        self.driver.get_vrouter = fake_vrouter_factory

    def test_create_router(self):
        router_id = _uuid()
        self.driver.create_router(router_id)

        svc_cache = self.driver._svc_cache
        self.assertEqual(len(svc_cache), 1)
        self.assertEqual(svc_cache[0]['router_id'], router_id)
        ipsec_connections = svc_cache[0]['ipsec_site_connections']
        self.assertEqual(
            ipsec_connections[0]['peer_address'],
            '172.24.4.234')

    def test_destroy_router(self):
        router_id = _uuid()
        self.driver.destroy_router(router_id)
        self.assertEqual(len(self.driver._svc_cache), 0)

    def test_sync(self):
        router_id = _uuid()
        self.driver.create_router(router_id)

        server_api = self.driver.server_api
        server_api.get_vpn_services_on_host.return_value = []
        self.driver.sync(mock.Mock(), None)

        self.driver._svc_delete.assert_called_once_with(mock.ANY, mock.ANY)