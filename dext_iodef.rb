require 'rubygems'
require 'nokogiri'


# Class for each <EventData> information
class EventData
  attr_accessor :source_address
  attr_accessor :source_node_role_category
  attr_accessor :source_port
  attr_accessor :source_operating_system_description
  attr_accessor :destination_address
  attr_accessor :destination_port

  def initialize
    @source_address = nil
    @source_node_role_category = nil
    @source_port = nil
    @source_operating_system_description = nil
    @destination_address = nil
    @destination_port = nil
  end
end

# Main class for DAEDALUS IODEF extension
class DextIODEF
  attr_accessor :incident_id
  attr_accessor :generation_time
  attr_accessor :report_time
  attr_accessor :description
  attr_accessor :system_impact_description
  attr_accessor :contact_name
  attr_accessor :contact_email
  attr_accessor :discovery_description

  def initialize
    dext = nil
    @incident_id = nil
    @generation_time = nil
    @report_time = nil
    @description = nil
    @system_impact_description = nil
    @contact_name = nil
    @contact_email = nil
    @discovery_description = nil
    @event_data = []
  end

  def add_event_data(ed)
    @event_data.push(ed)
  end

  def generate_xml
    dext = Nokogiri::XML::Builder.new do |xml|
      xml.send(:'IODEF-Document', 'version' =>  '2.00', 'xmlns' => 'urn:ietf:params:xml:ns:iodef-2.0',
                         'xmlns:iodef' => 'urn:ietf:params:xml:ns:iodef-2.0',
                         'xmlns:xsi' => 'http://www.w3.org/2001/XMLSchema-instance'
      ) do
        xml['iodef'].Incident('purpose' => 'reporting') do
          xml['iodef'].IncidentID('name' => 'csirt.example.com') do
            xml.text(@incident_id)
          end
          xml['iodef'].ReportTime do
            xml.text(@report_time)
          end
          xml['iodef'].GenerationTime do
            xml.text(@generation_time)
          end
          xml['iodef'].Description do
            xml.text(@description)
          end
          xml['iodef'].Assessment('occurrence' => 'potential') do
            xml['iodef'].SystemImpact('severity' => 'medium', 'type' => 'takeover-system') do
              xml['iodef'].Description do
                xml.text(@system_impact_description)
              end
            end
          end
          xml['iodef'].Contact('role' => 'creator', 'type' => 'organization') do
            xml['iodef'].ContactName do
              xml.text(@contact_name)
            end
            xml['iodef'].Email do
              xml['iodef'].EmailTo do
                xml.text(@contact_email)
              end
            end
          end
          @event_data.each do |ed|
            xml['iodef'].EventData do
              xml['iodef'].Discovery('source' => 'nidps') do
                xml['iodef'].Description do
                  xml.text(@discovery_description)
                end
              end
              xml['iodef'].Flow do
                xml['iodef'].System('category' => 'source') do
                  xml['iodef'].Node do
                    xml['iodef'].Address('category' => 'ipv4-addr') do
                      xml.text(ed.source_address)
                    end
                  end
                  xml['iodef'].NodeRole('category' => ed.source_node_role_category) do ####
                  end
                  xml['iodef'].Service('ip-protocol' => '6') do ####
                    xml['iodef'].Port do
                      xml.text(ed.source_port)
                    end
                  end
                  if ed.source_operating_system_description
                    xml['iodef'].OperatingSystem do
                      xml['iodef'].Description do
                        xml.text(ed.source_operating_system_description) ####
                      end
                    end
                  end
                end
              end
              xml['iodef'].Flow do
                xml['iodef'].System('category' => 'target') do
                  xml['iodef'].Node do
                    xml['iodef'].Address('category' => 'ipv4-addr') do
                      xml.text(ed.destination_address)
                    end
                  end
                  xml['iodef'].NodeRole('category' => 'honeypot') do ####
                  end
                  xml['iodef'].Service('ip-protocol' => '6') do ####
                    xml['iodef'].Port do
                      xml.text(ed.destination_port)
                    end
                  end
                end
              end
            end
          end
        end
      end
    end
    return dext.to_xml
  end
end