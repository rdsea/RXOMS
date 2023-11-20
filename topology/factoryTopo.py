from mininet.topo import Topo
import yaml  

class SinditTopo( Topo ):  
    "Simple star topology with single switch and 12 hosts"
    
    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )
        ip_config = {}
        # Add hosts and switches
        host_ssc = self.addHost( 'ssc' )
        host_mpo = self.addHost( 'mpo' )
        host_sld = self.addHost( 'sld' )
        host_hbw = self.addHost( 'hbw' )
        host_dps = self.addHost( 'dps' )
        host_vgr = self.addHost( 'vgr' )
        mqtt_gateway = self.addHost( 'mqttgw' )
        opcua_gateway = self.addHost( 'opcuagw' )
        ip_config['ssc'] = host_ssc.IP()
        ip_config['mpo'] = host_mpo.IP()
        ip_config['sld'] = host_sld.IP()
        ip_config['hbw'] = host_hbw.IP()
        ip_config['dps'] = host_dps.IP()
        ip_config['vgr'] = host_vgr.IP()
        ip_config['mqttgw'] = mqtt_gateway.IP()
        ip_config['opcuagw'] = opcua_gateway.IP()
        mqtt_switch = self.addSwitch('s1')
        opcua_switch = self.addSwitch('s2')
        with open('ip_config.yml', 'w') as f:
            yaml.dump(ip_config, f, default_flow_style=False)

        # Add links
        self.addLink( host_mpo, mqtt_switch )
        self.addLink( host_sld, mqtt_switch )
        self.addLink( host_dps, mqtt_switch )
        self.addLink( host_ssc, mqtt_switch )
        self.addLink( host_vgr, mqtt_switch )
        self.addLink( host_hbw, mqtt_switch )
        self.addLink( mqtt_gateway, mqtt_switch )
        self.addLink( opcua_gateway, opcua_switch )
        self.addLink( host_ssc, opcua_switch )
        self.addLink( host_vgr, opcua_switch )
        self.addLink( host_hbw, opcua_switch )


topos = { 'startopo': ( lambda: SinditTopo() ) }  