#!/usr/bin/env ruby

require 'time'
require './dext_iodef.rb'

# Create Main object
dext = DextIODEF.new
dext.incident_id = Time.now.to_i.to_s
dext.generation_time = Time.now.iso8601
dext.report_time = Time.now.iso8601
dext.description = 'Alerts from darknet monitoring system'
dext.system_impact_description = 'Scanning other hosts'
dext.contact_name = 'Example CSIRT'
dext.contact_email = 'contact@csirt.example.com'
dext.discovery_description = 'Detected by darknet monitoring'

# Example EventData 1
ed1 = EventData.new
ed1.source_address = '192.0.2.210'
ed1.source_node_role_category = 'camera'
ed1.source_port = '23'
ed1.source_operating_system_description = 'Example Surveillance Camera OS 2.1.1'
ed1.destination_address = '198.51.100.1'
ed1.destination_port = '23'


dext.add_event_data(ed1)


xml = dext.generate_xml
puts xml
