# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/wms"

# Copy-paste from grok_spec.rb, necessary to run grok filter
# running the grok code outside a logstash package means
# LOGSTASH_HOME will not be defined, so let's set it here
# before requiring the grok filter
unless LogStash::Environment.const_defined?(:LOGSTASH_HOME)
  LogStash::Environment::LOGSTASH_HOME = File.expand_path("../../../", __FILE__)
end
# End of copy-paste

describe LogStash::Filters::Wms do

  describe "regular calls logged into Varnish logs (apache combined)" do
    config <<-CONFIG
      filter {
        grok { match => { "message" => "%{COMBINEDAPACHELOG}" } }
        wms {}
      }
    CONFIG

    # regular WMS query (GetCapabilities) from varnish logs
    sample '12.13.14.15 - - [23/Jan/2014:06:52:00 +0100] "GET http://wms.myserver.com/?SERVICE=WMS&VERSION=1.3.0&REQUEST=GetCapabilities' \
    ' HTTP/1.1" 200 202 "http://referer.com" "ArcGIS Client Using WinInet"' do
      expect(subject["[wms][service]"]).to eq("WMS")
      expect(subject["[wms][version]"]).to eq("1.3.0")
      expect(subject["[wms][request]"]).to eq("GetCapabilities")
    end

    # WMS query (GetMap) from varnish logs
    sample '12.34.56.78 - - [23/Jan/2014:06:52:20 +0100] "GET http://tile2.wms.de/mapproxy/service/?FORMAT=image%2Fpng&LAYERS=WanderlandEtappenNational,WanderlandEtappenRegional,WanderlandEtappenLokal,WanderlandEtappenHandicap&TRANSPARENT=TRUE&SERVICE=WMS&VERSION=1.1.1&REQUEST=GetMap&STYLES=&SRS=EPSG%3A21781&BBOX=804000,30000,932000,158000&WIDTH=256&HEIGHT=256 HTTP/1.1" 200 1447 "http://map.wanderland.ch/?lang=de&route=all&layer=wanderwegnetz" "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; Trident/6.0)"' do
       expect(subject["[wms][service]"]).to eq("WMS")
       expect(subject["[wms][version]"]).to eq("1.1.1")
       expect(subject["[wms][request]"]).to eq("GetMap")
       expect(subject["[wms][layers]"]).to eq(["WanderlandEtappenNational", "WanderlandEtappenRegional", "WanderlandEtappenLokal", "WanderlandEtappenHandicap"])
       expect(subject["[wms][styles]"]).to eq("")
       expect(subject["[wms][srs]"]).to eq("EPSG:21781")
       expect(subject["[wms][input_bbox][minx]"]).to eq(804000.0)
       expect(subject["[wms][input_bbox][miny]"]).to eq(30000.0)
       expect(subject["[wms][input_bbox][maxx]"]).to eq(932000.0)
       expect(subject["[wms][input_bbox][maxy]"]).to eq(158000.0)
       expect(subject["[wms][output_bbox][minx]"]).to eq(10.043259272201887)
       expect(subject["[wms][output_bbox][miny]"]).to eq(45.39141145053888)
       expect(subject["[wms][output_bbox][maxx]"]).to eq(11.764979420793644)
       expect(subject["[wms][output_bbox][maxy]"]).to eq(46.49090648227697)
       expect(subject["[wms][width]"]).to eq("256")
       expect(subject["[wms][height]"]).to eq("256")
       expect(subject["[wms][format]"]).to eq("image/png")
       expect(subject["[wms][transparent]"]).to eq("TRUE")
     end
  end
  # we will now use only the request part without grok for readability
  describe "regular calls (message containing only the request URI)" do
    config <<-CONFIG
      filter {
        wms {}
      }
    CONFIG
    # illegal SRS provided
    sample 'http://tile2.wms.de/mapproxy/service/?SERVICE=WmS&SRS=EPSG%3A9999999&BBOX=804000,30000,932000,158000' do
      expect(subject["[wms][errmsg]"]).to eq("Unable to reproject the bounding box")
    end
    # no reprojection needed
    sample 'http://tile2.wms.de/mapproxy/service/?SERVICE=WmS&SRS=EPSG%3A4326&BBOX=804000,30000,932000,158000' do
      expect(subject["[wms][input_bbox][minx]"]).to eq(subject["[wms][output_bbox][minx]"])
      expect(subject["[wms][input_bbox][miny]"]).to eq(subject["[wms][output_bbox][miny]"])
      expect(subject["[wms][input_bbox][maxx]"]).to eq(subject["[wms][output_bbox][maxx]"])
      expect(subject["[wms][input_bbox][maxy]"]).to eq(subject["[wms][output_bbox][maxy]"])
    end
    # bbox provided without SRS (probably not valid in WMS standard)
    # no reproj needed either
    sample 'http://tile2.wms.de/mapproxy/service/?SERVICE=WmS&BBOX=804000,30000,932000,158000' do
      expect(subject["[wms][input_bbox][minx]"]).to eq(subject["[wms][output_bbox][minx]"])
      expect(subject["[wms][input_bbox][miny]"]).to eq(subject["[wms][output_bbox][miny]"])
      expect(subject["[wms][input_bbox][maxx]"]).to eq(subject["[wms][output_bbox][maxx]"])
      expect(subject["[wms][input_bbox][maxy]"]).to eq(subject["[wms][output_bbox][maxy]"])
    end
    # illegal bbox provided
    sample 'http://tile2.wms.de/mapproxy/service/?SERVICE=WmS&CRS=EPSG%3A2154&BBOX=8040NOTAVALIDBBOX93084' do
      expect(subject["[wms][errmsg]"]).to eq("Unable to parse the bounding box")
    end
    # Unparseable URL provided
    sample 'this is not a valid url, service=wms' do
      expect(subject["[wms][errmsg]"]).to start_with("Unable to parse the provided request URI:")
    end
  end
end
