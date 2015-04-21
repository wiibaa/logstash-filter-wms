# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

#
# This filter converts data from OGC WMTS (Web Map Tile Service) URLs to
# geospatial information, and expands the logstash event accordingly. See
# http://www.opengeospatial.org/standards/wmts for more information about WMTS. 
#
# Given a grid, WMTS urls contain all the necessary information to find out
# which coordinates a requested tile belongs to.  Using a simple grok filter
# you can extract all the relevant information. This plugin then translates
# these information into coordinates in LV03 and WGS84.
#
# Here is an example of such a request: 
# http://wmts4.geo.admin.ch/1.0.0/ch.swisstopo.pixelkarte-farbe/default/20130213/21781/23/470/561.jpeg
#
# The current filter can be configured as follows in the configuration file:
# [source,ruby]
# filter {
#   # First, waiting for varnish log file formats (combined apache logs)
#   grok { match => [ "message", "%{COMBINEDAPACHELOG}" ] }
#   # Then, parameters
#   grok {
#     match => {
#       "request" => "https?://%{IPORHOST}/%{DATA:[wmts][version]}/%{DATA:[wmts][layer]}/default/%{POSINT:[wmts][release]}/%{DATA:[wmts][reference-system]}/%{POSINT:[wmts][zoomlevel]}/%{POSINT:[wmts][row]}/%{POSINT:[wmts][col]}\.%{WORD:[wmts][filetype]}" 
#     }
#   }
#   # actually passes the previously parsed message to the wmts plugin
#   wmts { }
#  }
#
# By default, the filter is configured to parse requests made on WMTS servers
# configured with the Swisstopo WMTS grid, but this can be customized through 
# the `x_origin`,`y_origin`,`tile_width`,`tile_height` and `resolutions` parameters.
#
class LogStash::Filters::Wmts < LogStash::Filters::Base

  config_name "wmts"

  # Specify the abscissa origin of the WMTS grid
  #(by default, it is set to Swisstopo's WMTS grid)
  config :x_origin, :validate => :number, :default => 420000
  
  # Specify the ordinate origin of the WMTS
  #(by default, it is set to Swisstopo's WMTS grid)
  config :y_origin, :validate => :number, :default => 350000
  
  # Specify the width of the produced image tiles
  config :tile_width, :validate => :number, :default => 256

  # Specify the height of the produced image tiles
  config :tile_height, :validate => :number, :default => 256
  
  # Specify the array of resolutions for this WMTS grid
  config :resolutions, :validate => :array, :default => [ 4000, 3750, 3500, 3250, 3000, 2750, 2500, 2250, 2000,
        1750, 1500, 1250, 1000, 750, 650, 500, 250, 100, 50, 20, 10, 5, 2.5, 2, 1.5, 1, 0.5, 0.25, 0.1 ]

  # Specify the field into which Logstash should store the wms data.
  config :target, :validate => :string, :default => "wmts"

  # Specify the output projection to be used when setting the x/y
  # coordinates, default to regular lat/long wgs84 ('epsg:4326')
  config :output_epsg, :validate => :string, :default => "epsg:4326"

  # Specify the name of the field where the filter can find the WMTS zoomlevel
  config :zoomlevel_field, :validate => :string, :default => "[wmts][zoomlevel]"

  # Specify the name of the field where the filter can find the WMTS column
  config :column_field, :validate => :string, :default => "[wmts][col]"

  # Specify the name of the field where the filter can find the WMTS row
  config :row_field, :validate => :string, :default => "[wmts][row]"

  # Specify the name of the field where the filter can find the WMTS reference system
  # Note: if the reference system is different from the output_epsg, 
  # a reprojection of the coordinates will take place.
  config :refsys_field, :validate => :string, :default => "[wmts][reference-system]"
  
  # Specify mapping between named projections and their actual EPSG code.
  # Sometimes, the reference-system can be given as a string ('swissgrid' for instance). 
  # This parameter allows to set a mapping between 
  # a regular name and the epsg number of a projection, e.g.:
  # [source;ruby]
  #   { "swissgrid" => 21781 }
  #
  config :epsg_mapping, :validate => :hash, :default => {} 

  public
  def register
    require "geoscript"
  end

  public
  def filter(event)
    begin
      # cast values extracted upstream into integers
      zoomlevel = Integer(event[@zoomlevel_field])
      col = Integer(event[@column_field])
      row = Integer(event[@row_field])

      # checks if a mapping exists for the reference system extracted
      translated_epsg = @epsg_mapping[event[@refsys_field]] || event[@refsys_field] 
      input_epsg = "epsg:#{translated_epsg}"

      resolution = @resolutions[zoomlevel]
      raise ArgumentError if resolution.nil?
    rescue ArgumentError, TypeError, NoMethodError
      event["[#{@target}][errmsg]"] = "Bad parameter received from upstream filter"
      return
    end

    begin
      input_x = @x_origin + (((col+0.5)*@tile_width*resolution).floor)
      input_y = @y_origin - (((row+0.5)*@tile_height*resolution).floor)

      event["[#{@target}][service]"] = "wmts"

      event["[#{@target}][input_epsg]"] = input_epsg
      event["[#{@target}][input_x]"] = input_x
      event["[#{@target}][input_y]"] = input_y
      # add a combined field to the event. used for elaticsearch facets (heatmap!)
      event["[#{@target}][input_xy]"] = "#{input_x},#{input_y}"

      # convert from input_epsg to output_epsg (if necessary)
      event["[#{@target}][output_epsg]"] = @output_epsg

      unless input_epsg == @output_epsg
        input_p = GeoScript::Geom::Point.new input_x, input_y
        output_p = GeoScript::Projection.reproject input_p, input_epsg, @output_epsg
        event["[#{@target}][output_xy]"] = "#{output_p.x},#{output_p.y}"
        event["[#{@target}][output_x]"] = output_p.x
        event["[#{@target}][output_y]"] = output_p.y
      else
        # no reprojection needed
        event["[#{@target}][output_xy]"] = "#{input_x},#{input_y}"
        event["[#{@target}][output_x]"] = input_x
        event["[#{@target}][output_y]"] = input_y
      end
    rescue 
      event["[#{@target}][errmsg]"] = "Unable to reproject tile coordinates"
    end
    filter_matched(event)
  end # def filter
end
