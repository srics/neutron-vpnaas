# Copyright 2014 OpenStack Foundation.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# @author: Karthik Natarajan (natarajk@brocade.com)
#

from neutron.agent.l3 import agent as l3_agent
from neutron.openstack.common import log as logging
from neutron.plugins.brocade.vyatta.common import l3_agent as vyatta_l3
from neutron_vpnaas.services.vpn.device_drivers import vyatta_ipsec
from neutron.agent import l3_agent as entry
from neutron_vpnaas.services.vpn import vpn_service
from oslo.config import cfg

LOG = logging.getLogger(__name__)

vpn_agent_opts = [
    cfg.MultiStrOpt(
        'vpn_device_driver',
        default=['neutron_vpnaas.services.vpn.device_drivers.'
                 'vyatta_ipsec.VyattaIPSecDriver'],
        help=_("The vpn device drivers Neutron will use")),
]
cfg.CONF.register_opts(vpn_agent_opts, 'vpnagent')


class VyattaVPNAgent(vyatta_l3.L3AgentMiddleware):
    def __init__(self, host, conf=None):
        super(VyattaVPNAgent, self).__init__(host, conf)
        # VPN device drivers
        # self.vpn_devices = [
        #     vyatta_ipsec.VyattaIPSecDriver(self, host)]
        # NOTE: Temp location for creating service and loading drivers
        self.service = vpn_service.VPNService.instance(self)
        self.event_observers.add(self.service)
        self.devices = self.service.load_device_drivers(host)


    def _process_router_if_compatible(self, router):
        LOG.debug('Vyatta vRouter: vyatta_agent: Handling _process_router_if_compatible')
        super(VyattaVPNAgent, self)._process_router_if_compatible(router)
        for device in self.devices:
            device.sync(self.context, None)


def main():
    entry.main(
        manager='neutron_vpnaas.services.vpn.vyatta_agent.VyattaVPNAgent')

