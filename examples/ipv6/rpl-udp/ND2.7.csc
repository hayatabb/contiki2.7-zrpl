<?xml version="1.0" encoding="UTF-8"?>
<simconf>
  <project EXPORT="discard">[APPS_DIR]/mrm</project>
  <project EXPORT="discard">[APPS_DIR]/mspsim</project>
  <project EXPORT="discard">[APPS_DIR]/avrora</project>
  <project EXPORT="discard">[APPS_DIR]/serial_socket</project>
  <project EXPORT="discard">[APPS_DIR]/collect-view</project>
  <project EXPORT="discard">[APPS_DIR]/powertracker</project>
  <simulation>
    <title>ND2.7</title>
    <randomseed>123456</randomseed>
    <motedelay_us>1000000</motedelay_us>
    <radiomedium>
      se.sics.cooja.radiomediums.UDGM
      <transmitting_range>50.0</transmitting_range>
      <interference_range>100.0</interference_range>
      <success_ratio_tx>1.0</success_ratio_tx>
      <success_ratio_rx>1.0</success_ratio_rx>
    </radiomedium>
    <events>
      <logoutput>40000</logoutput>
    </events>
    <motetype>
      se.sics.cooja.mspmote.SkyMoteType
      <identifier>sky1</identifier>
      <description>edge</description>
      <firmware EXPORT="copy">[CONTIKI_DIR]/examples/ipv6/rpl-udp/udp-server.sky</firmware>
      <moteinterface>se.sics.cooja.mspmote.interfaces.MspPosition</moteinterface>
      <moteinterface>se.sics.cooja.interfaces.RimeAddress</moteinterface>
      <moteinterface>se.sics.cooja.interfaces.IPAddress</moteinterface>
      <moteinterface>se.sics.cooja.interfaces.Mote2MoteRelations</moteinterface>
      <moteinterface>se.sics.cooja.interfaces.MoteAttributes</moteinterface>
      <moteinterface>se.sics.cooja.mspmote.interfaces.MspClock</moteinterface>
      <moteinterface>se.sics.cooja.mspmote.interfaces.MspMoteID</moteinterface>
      <moteinterface>se.sics.cooja.mspmote.interfaces.SkyButton</moteinterface>
      <moteinterface>se.sics.cooja.mspmote.interfaces.SkyFlash</moteinterface>
      <moteinterface>se.sics.cooja.mspmote.interfaces.SkyCoffeeFilesystem</moteinterface>
      <moteinterface>se.sics.cooja.mspmote.interfaces.Msp802154Radio</moteinterface>
      <moteinterface>se.sics.cooja.mspmote.interfaces.MspSerial</moteinterface>
      <moteinterface>se.sics.cooja.mspmote.interfaces.SkyLED</moteinterface>
      <moteinterface>se.sics.cooja.mspmote.interfaces.MspDebugOutput</moteinterface>
      <moteinterface>se.sics.cooja.mspmote.interfaces.SkyTemperature</moteinterface>
    </motetype>
    <motetype>
      se.sics.cooja.mspmote.SkyMoteType
      <identifier>sky2</identifier>
      <description>router</description>
      <firmware EXPORT="copy">[CONTIKI_DIR]/examples/ipv6/rpl-udp/udp-client.sky</firmware>
      <moteinterface>se.sics.cooja.mspmote.interfaces.MspPosition</moteinterface>
      <moteinterface>se.sics.cooja.interfaces.RimeAddress</moteinterface>
      <moteinterface>se.sics.cooja.interfaces.IPAddress</moteinterface>
      <moteinterface>se.sics.cooja.interfaces.Mote2MoteRelations</moteinterface>
      <moteinterface>se.sics.cooja.interfaces.MoteAttributes</moteinterface>
      <moteinterface>se.sics.cooja.mspmote.interfaces.MspClock</moteinterface>
      <moteinterface>se.sics.cooja.mspmote.interfaces.MspMoteID</moteinterface>
      <moteinterface>se.sics.cooja.mspmote.interfaces.SkyButton</moteinterface>
      <moteinterface>se.sics.cooja.mspmote.interfaces.SkyFlash</moteinterface>
      <moteinterface>se.sics.cooja.mspmote.interfaces.SkyCoffeeFilesystem</moteinterface>
      <moteinterface>se.sics.cooja.mspmote.interfaces.Msp802154Radio</moteinterface>
      <moteinterface>se.sics.cooja.mspmote.interfaces.MspSerial</moteinterface>
      <moteinterface>se.sics.cooja.mspmote.interfaces.SkyLED</moteinterface>
      <moteinterface>se.sics.cooja.mspmote.interfaces.MspDebugOutput</moteinterface>
      <moteinterface>se.sics.cooja.mspmote.interfaces.SkyTemperature</moteinterface>
    </motetype>
    <mote>
      <breakpoints>
        <breakpoint>
          <stops>false</stops>
          <codefile>[CONTIKI_DIR]/core/net/rpl/rpl-icmp6.c</codefile>
          <line>343</line>
          <contikicode>buffer = UIP_ICMP_PAYLOAD;</contikicode>
          <color>-16777216</color>
        </breakpoint>
        <breakpoint>
          <stops>false</stops>
          <codefile>[CONTIKI_DIR]/core/net/rpl/rpl-icmp6.c</codefile>
          <line>376</line>
          <contikicode>PRINT6ADDR(&amp;prefix);</contikicode>
          <color>-16777216</color>
        </breakpoint>
      </breakpoints>
      <interface_config>
        se.sics.cooja.mspmote.interfaces.MspPosition
        <x>57.0463498585973</x>
        <y>31.91056563001246</y>
        <z>0.0</z>
      </interface_config>
      <interface_config>
        se.sics.cooja.mspmote.interfaces.MspMoteID
        <id>1</id>
      </interface_config>
      <motetype_identifier>sky1</motetype_identifier>
    </mote>
    <mote>
      <breakpoints>
        <breakpoint>
          <stops>false</stops>
          <codefile>[CONTIKI_DIR]/core/net/rpl/rpl.c</codefile>
          <line>228</line>
          <contikicode>debug_test1 = sizeof(rpl_selfinfo_t);</contikicode>
          <color>-16777216</color>
        </breakpoint>
        <breakpoint>
          <stops>false</stops>
          <codefile>[CONTIKI_DIR]/core/net/rpl/rpl-icmp6.c</codefile>
          <line>136</line>
          <contikicode>uip_ipaddr_copy(&amp;from, &amp;UIP_IP_BUF-&gt;srcipaddr);</contikicode>
          <color>-16777216</color>
        </breakpoint>
        <breakpoint>
          <stops>false</stops>
          <codefile>[CONTIKI_DIR]/core/net/rpl/rpl-icmp6.c</codefile>
          <line>430</line>
          <contikicode>dio_input();</contikicode>
          <color>-16777216</color>
        </breakpoint>
        <breakpoint>
          <stops>false</stops>
          <codefile>[CONTIKI_DIR]/core/net/rpl/rpl-icmp6.c</codefile>
          <line>427</line>
          <contikicode>switch(UIP_ICMP_BUF-&gt;icode) {</contikicode>
          <color>-16777216</color>
        </breakpoint>
      </breakpoints>
      <interface_config>
        se.sics.cooja.mspmote.interfaces.MspPosition
        <x>45.39289385640722</x>
        <y>22.811704199475038</y>
        <z>0.0</z>
      </interface_config>
      <interface_config>
        se.sics.cooja.mspmote.interfaces.MspMoteID
        <id>2</id>
      </interface_config>
      <motetype_identifier>sky2</motetype_identifier>
    </mote>
    <mote>
      <breakpoints />
      <interface_config>
        se.sics.cooja.mspmote.interfaces.MspPosition
        <x>28.713597194403444</x>
        <y>33.467921511310784</y>
        <z>0.0</z>
      </interface_config>
      <interface_config>
        se.sics.cooja.mspmote.interfaces.MspMoteID
        <id>3</id>
      </interface_config>
      <motetype_identifier>sky2</motetype_identifier>
    </mote>
    <mote>
      <breakpoints />
      <interface_config>
        se.sics.cooja.mspmote.interfaces.MspPosition
        <x>82.45799754974895</x>
        <y>29.76141114197661</y>
        <z>0.0</z>
      </interface_config>
      <interface_config>
        se.sics.cooja.mspmote.interfaces.MspMoteID
        <id>4</id>
      </interface_config>
      <motetype_identifier>sky2</motetype_identifier>
    </mote>
    <mote>
      <breakpoints />
      <interface_config>
        se.sics.cooja.mspmote.interfaces.MspPosition
        <x>71.47297165264482</x>
        <y>49.84904733413027</y>
        <z>0.0</z>
      </interface_config>
      <interface_config>
        se.sics.cooja.mspmote.interfaces.MspMoteID
        <id>5</id>
      </interface_config>
      <motetype_identifier>sky2</motetype_identifier>
    </mote>
    <mote>
      <breakpoints />
      <interface_config>
        se.sics.cooja.mspmote.interfaces.MspPosition
        <x>56.97273746846735</x>
        <y>37.855026465736564</y>
        <z>0.0</z>
      </interface_config>
      <interface_config>
        se.sics.cooja.mspmote.interfaces.MspMoteID
        <id>6</id>
      </interface_config>
      <motetype_identifier>sky2</motetype_identifier>
    </mote>
  </simulation>
  <plugin>
    se.sics.cooja.plugins.SimControl
    <width>280</width>
    <z>1</z>
    <height>160</height>
    <location_x>400</location_x>
    <location_y>0</location_y>
  </plugin>
  <plugin>
    se.sics.cooja.plugins.Visualizer
    <plugin_config>
      <moterelations>true</moterelations>
      <skin>se.sics.cooja.plugins.skins.IDVisualizerSkin</skin>
      <skin>se.sics.cooja.plugins.skins.GridVisualizerSkin</skin>
      <skin>se.sics.cooja.plugins.skins.TrafficVisualizerSkin</skin>
      <skin>se.sics.cooja.plugins.skins.UDGMVisualizerSkin</skin>
      <skin>se.sics.cooja.plugins.skins.MoteTypeVisualizerSkin</skin>
      <skin>se.sics.cooja.plugins.skins.PositionVisualizerSkin</skin>
      <viewport>5.586116677231774 0.0 0.0 5.586116677231774 -90.25635892015305 -26.462594657301214</viewport>
    </plugin_config>
    <width>400</width>
    <z>0</z>
    <height>400</height>
    <location_x>4</location_x>
    <location_y>-12</location_y>
  </plugin>
  <plugin>
    se.sics.cooja.plugins.LogListener
    <plugin_config>
      <filter />
      <formatted_time />
      <coloring />
    </plugin_config>
    <width>701</width>
    <z>2</z>
    <height>240</height>
    <location_x>400</location_x>
    <location_y>160</location_y>
  </plugin>
  <plugin>
    se.sics.cooja.plugins.TimeLine
    <plugin_config>
      <mote>0</mote>
      <mote>1</mote>
      <mote>2</mote>
      <mote>3</mote>
      <mote>4</mote>
      <mote>5</mote>
      <showRadioRXTX />
      <showRadioHW />
      <showLEDs />
      <zoomfactor>500.0</zoomfactor>
    </plugin_config>
    <width>1101</width>
    <z>3</z>
    <height>216</height>
    <location_x>42</location_x>
    <location_y>357</location_y>
  </plugin>
  <plugin>
    se.sics.cooja.plugins.Notes
    <plugin_config>
      <notes>Enter notes here</notes>
      <decorations>true</decorations>
    </plugin_config>
    <width>421</width>
    <z>4</z>
    <height>160</height>
    <location_x>680</location_x>
    <location_y>0</location_y>
  </plugin>
  <plugin>
    se.sics.cooja.plugins.VariableWatcher
    <mote_arg>1</mote_arg>
    <plugin_config>
      <varname>uip_aligned_buf</varname>
      <vartype>array</vartype>
      <array_length>10</array_length>
    </plugin_config>
    <width>482</width>
    <z>6</z>
    <height>228</height>
    <location_x>-640</location_x>
    <location_y>15</location_y>
  </plugin>
  <plugin>
    se.sics.cooja.plugins.VariableWatcher
    <mote_arg>0</mote_arg>
    <plugin_config>
      <varname>debug_test1</varname>
      <vartype>byte</vartype>
    </plugin_config>
    <width>436</width>
    <z>5</z>
    <height>199</height>
    <location_x>-1224</location_x>
    <location_y>205</location_y>
  </plugin>
</simconf>

