from mininet.topo import Topo  

class SinditTopo( Topo ):  
    "Simple star topology with single switch and 12 hosts"
    
    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add hosts and switches
        host_ssc = self.addHost( 'ssc' )
        host_mpo = self.addHost( 'mpo' )
        host_sld = self.addHost( 'sld' )
        host_hbw = self.addHost( 'hbw' )
        host_dps = self.addHost( 'dps' )
        host_vgr = self.addHost( 'vgr' )
        mqtt_gateway = self.addHost( 'mqttgw' )
        opcua_gateway = self.addHost( 'ocpuagw' )
        mqtt_switch = self.addSwitch('s1')
        opcua_switch = self.addSwitch('s2')

        # Add links
        self.addLink( host_mpo, mqtt_switch )
        self.addLink( host_sld, mqtt_switch )
        self.addLink( host_dps, mqtt_switch )
        # self.addLink( host_ssc, mqtt_switch )
        # self.addLink( host_vgr, mqtt_switch )
        # self.addLink( host_hbw, mqtt_switch )
        self.addLink( mqtt_gateway, mqtt_switch )
        self.addLink( opcua_gateway, opcua_switch )
        self.addLink( mqtt_switch, opcua_switch )
        self.addLink( host_ssc, opcua_switch )
        self.addLink( host_vgr, opcua_switch )
        self.addLink( host_hbw, opcua_switch )


topos = { 'startopo': ( lambda: SinditTopo() ) }  