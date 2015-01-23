import netaddr

from neutron.common import rpc as n_rpc
from neutron_vpnaas.services.vpn.common import topics
from neutron_vpnaas.services.vpn.service_drivers import ipsec
from neutron_vpnaas.services.vpn import service_drivers

IPSEC = 'ipsec'
BASE_IPSEC_VERSION = '1.0'


class VyattaIPsecDriver(service_drivers.VpnDriver):

    def __init__(self, service_plugin):
        super(VyattaIPsecDriver, self).__init__(service_plugin)

        self.endpoints = [ipsec.IPsecVpnDriverCallBack(self)]
        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(
            topics.BROCADE_IPSEC_DRIVER_TOPIC, self.endpoints, fanout=False)
        self.conn.consume_in_threads()
        self.agent_rpc = ipsec.IPsecVpnAgentApi(
            topics.BROCADE_IPSEC_AGENT_TOPIC, BASE_IPSEC_VERSION, self)

    @property
    def service_type(self):
        return IPSEC

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        vpnservice = self.service_plugin._get_vpnservice(
            context, ipsec_site_connection['vpnservice_id'])
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])

    def update_ipsec_site_connection(
        self, context, old_ipsec_site_connection, ipsec_site_connection):
        vpnservice = self.service_plugin._get_vpnservice(
            context, ipsec_site_connection['vpnservice_id'])
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])

    def delete_ipsec_site_connection(self, context, ipsec_site_connection):
        vpnservice = self.service_plugin._get_vpnservice(
            context, ipsec_site_connection['vpnservice_id'])
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])

    def create_ikepolicy(self, context, ikepolicy):
        pass

    def delete_ikepolicy(self, context, ikepolicy):
        pass

    def update_ikepolicy(self, context, old_ikepolicy, ikepolicy):
        pass

    def create_ipsecpolicy(self, context, ipsecpolicy):
        pass

    def delete_ipsecpolicy(self, context, ipsecpolicy):
        pass

    def update_ipsecpolicy(self, context, old_ipsec_policy, ipsecpolicy):
        pass

    def create_vpnservice(self, context, vpnservice):
        pass

    def update_vpnservice(self, context, old_vpnservice, vpnservice):
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])

    def delete_vpnservice(self, context, vpnservice):
        self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])

    def _make_vpnservice_dict(self, vpnservice):
        """Convert vpnservice information for vpn agent.

        also converting parameter name for vpn agent driver
        """
        vpnservice_dict = dict(vpnservice)
        vpnservice_dict['ipsec_site_connections'] = []
        vpnservice_dict['subnet'] = dict(
            vpnservice.subnet)
        vpnservice_dict['external_ip'] = vpnservice.router.gw_port[
            'fixed_ips'][0]['ip_address']
        for ipsec_site_connection in vpnservice.ipsec_site_connections:
            ipsec_site_connection_dict = dict(ipsec_site_connection)
            try:
                netaddr.IPAddress(ipsec_site_connection['peer_id'])
            except netaddr.core.AddrFormatError:
                ipsec_site_connection['peer_id'] = (
                    '@' + ipsec_site_connection['peer_id'])
            ipsec_site_connection_dict['ikepolicy'] = dict(
                ipsec_site_connection.ikepolicy)
            ipsec_site_connection_dict['ipsecpolicy'] = dict(
                ipsec_site_connection.ipsecpolicy)
            vpnservice_dict['ipsec_site_connections'].append(
                ipsec_site_connection_dict)
            peer_cidrs = [
                peer_cidr.cidr
                for peer_cidr in ipsec_site_connection.peer_cidrs]
            ipsec_site_connection_dict['peer_cidrs'] = peer_cidrs
        return vpnservice_dict
