# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/filters/wmts"

describe LogStash::Filters::Wmts do

  describe "regular calls logged into Varnish logs (apache combined)" do
    config <<-CONFIG
      filter {
        # First, waiting for varnish log file formats (combined apache logs)
        grok { match => [ "message", "%{COMBINEDAPACHELOG}" ] }
        # Then, parameters 
        # Note: the 'wmts.' prefix should match the configuration of the plugin,
        # e.g if "wmts { 'prefix' => 'gis' }", then you should adapt the grok filter
        # accordingly.
        #
        grok {
          match => {
            #"request" => "(?<[wmts][version]\">([0-9\.]{5}))\/(?<[wmts][layer]>([a-z0-9\.-]*))\/default\/(?<[wmts][release]>([0-9]{8}))\/(?<[wmts][reference-system]>([0-9]*))\/(?<[wmts][zoomlevel]>([0-9]*))\/(?<[wmts][row]>([0-9]*))\/(?<[wmts][col]>([0-9]*))\.(?<[wmts][filetype]>([a-zA-Z]*))"
            "request" => "https?://%{IPORHOST}/%{DATA:[wmts][version]}/%{DATA:[wmts][layer]}/default/%{POSINT:[wmts][release]}/%{POSINT:[wmts][reference-system]}/%{POSINT:[wmts][zoomlevel]}/%{POSINT:[wmts][row]}/%{POSINT:[wmts][col]}\.%{WORD:[wmts][filetype]}"
          }
        }
        wmts { }
      }
    CONFIG

    # regular WMTS query from a varnish log
    sample '127.0.0.1 - - [20/Jan/2014:16:48:28 +0100] "GET http://wmts4.testserver.org/1.0.0/' \
      'mycustomlayer/default/20130213/21781/23/470/561.jpeg HTTP/1.1" 200 2114 ' \
      '"http://localhost/ajaxplorer/" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36' \
      '(KHTML, like Gecko) Ubuntu Chromium/31.0.1650.63 Chrome/31.0.1650.63 Safari/537.36"' do
        # checks that the query has been successfully parsed  
        # and the geopoint correctly reprojected into wgs:84 
        expect(subject["[wmts][version]"]).to eq("1.0.0")
        expect(subject["[wmts][layer]"]).to eq("mycustomlayer")
        expect(subject["[wmts][release]"]).to eq("20130213")
        expect(subject["[wmts][reference-system]"]).to eq("21781")
        expect(subject["[wmts][zoomlevel]"]).to eq("23")
        expect(subject["[wmts][row]"]).to eq("470")
        expect(subject["[wmts][col]"]).to eq("561")
        expect(subject["[wmts][filetype]"]).to eq("jpeg")
        expect(subject["[wmts][service]"]).to eq("wmts")
        expect(subject["[wmts][input_epsg]"]).to eq("epsg:21781")
        expect(subject["[wmts][input_x]"]).to eq(707488)
        expect(subject["[wmts][input_y]"]).to eq(109104)
        expect(subject["[wmts][input_xy]"]).to eq("707488,109104")
        expect(subject["[wmts][output_epsg]"]).to eq("epsg:4326")
        expect(subject["[wmts][output_xy]"]).to eq("8.829295858079231,46.12486163053951")
        expect(subject["[wmts][output_x]"]).to eq(8.829295858079231)
        expect(subject["[wmts][output_y]"]).to eq(46.12486163053951)
      end

    # query extracted from a varnish log, but not matching a wmts request
    sample '83.77.200.25 - - [23/Jan/2014:06:51:55 +0100] "GET http://map.schweizmobil.ch/api/api.css HTTP/1.1"' \
      ' 200 682 "http://www.schaffhauserland.ch/de/besenbeiz" ' \
      '"Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"' do
        expect(subject["tags"]).to include("_grokparsefailure")
    end

    # query looking like a legit wmts log but actually contains garbage [1]
    # - parameters from the grok filter cannot be cast into integers
    sample '127.0.0.1 - - [20/Jan/2014:16:48:28 +0100] "GET http://wmts4.testserver.org/1.0.0/' \
      'mycustomlayer/default/12345678////.raw HTTP/1.1" 200 2114 ' \
      '"http://localhost//" "ozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36' \
      '(KHTML, like Gecko) Ubuntu Chromium/31.0.1650.63 Chrome/31.0.1650.63 Safari/537.36"' do
         expect(subject["[wmts][errmsg]"]).to start_with("Bad parameter received")
    end

    # query looking like a legit wmts log but actually contains garbage
    # * 99999999 is not a valid EPSG code (but still parseable as an integer)
    sample '127.0.0.1 - - [20/Jan/2014:16:48:28 +0100] "GET http://wmts4.testserver.org/1.0.0/' \
      'mycustomlayer/default/20130213/99999999/23/470/561.jpeg HTTP/1.1" 200 2114 ' \
      '"http://localhost//" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36' \
      '(KHTML, like Gecko) Ubuntu Chromium/31.0.1650.63 Chrome/31.0.1650.63 Safari/537.36"' do
         expect(subject['[wmts][errmsg]']).to eq("Unable to reproject tile coordinates")
    end
  end

  describe "Testing the epsg_mapping parameter" do
    config <<-CONFIG
      filter {
        grok { match => [ "message", "%{COMBINEDAPACHELOG}" ] }
        grok {
          match => {
            # "request" => "(?<wmts.version>([0-9\.]{5}))\/(?<wmts.layer>([a-z0-9\.-]*))\/default\/(?<wmts.release>([0-9]*))\/(?<wmts.reference-system>([a-z0-9]*))\/(?<wmts.zoomlevel>([0-9]*))\/(?<wmts.row>([0-9]*))\/(?<wmts.col>([0-9]*))\.(?<wmts.filetype>([a-zA-Z]*))"
            "request" => "https?://%{IPORHOST}/%{DATA:[wmts][version]}/%{DATA:[wmts][layer]}/default/%{POSINT:[wmts][release]}/%{DATA:[wmts][reference-system]}/%{POSINT:[wmts][zoomlevel]}/%{POSINT:[wmts][row]}/%{POSINT:[wmts][col]}\.%{WORD:[wmts][filetype]}"
          }
        }
        wmts { epsg_mapping => { 'swissgrid' => 21781 } }
      }
    CONFIG

    # regular query needing a mapping
    sample '11.12.13.14 - - [10/Feb/2014:16:27:26 +0100] "GET http://tile1.wmts.example.org/1.0.0/grundkarte/default/2013/swissgrid/9/371/714.png HTTP/1.1" 200 8334 "http://example.org" "Mozilla/5.0 (Windows NT 6.1; rv:26.0) Gecko/20100101 Firefox/26.0"' do
      puts subject.to_hash
      expect(subject["[wmts][version]"]).to eq("1.0.0")
      expect(subject["[wmts][layer]"]).to eq("grundkarte")
      expect(subject["[wmts][release]"]).to eq("2013")
      expect(subject["[wmts][reference-system]"]).to eq("swissgrid")
      expect(subject["[wmts][zoomlevel]"]).to eq("9")
      expect(subject["[wmts][row]"]).to eq("371")
      expect(subject["[wmts][col]"]).to eq("714")
      expect(subject["[wmts][filetype]"]).to eq("png")
      expect(subject["[wmts][service]"]).to eq("wmts")
      # it should have been correctly mapped
      expect(subject["[wmts][input_epsg]"]).to eq("epsg:21781")
      expect(subject["[wmts][input_x]"]).to eq(320516000)
      expect(subject["[wmts][input_y]"]).to eq(-166082000)
      expect(subject["[wmts][input_xy]"]).to eq("320516000,-166082000")
      expect(subject["[wmts][output_epsg]"]).to eq("epsg:4326")
      expect(subject["[wmts][output_xy]"]).to eq("7.438691675813199,-43.38015041464443")
      expect(subject["[wmts][output_x]"]).to eq(7.438691675813199)
      expect(subject["[wmts][output_y]"]).to eq(-43.38015041464443)
    end
 
    # regular query which does not need a mapping
    sample '11.12.13.14 - - [10/Feb/2014:16:27:26 +0100] "GET http://tile1.wmts.example.org/1.0.0/grundkarte/default/2013/21781/9/371/714.png HTTP/1.1" 200 8334 "http://example.org" "Mozilla/5.0 (Windows NT 6.1; rv:26.0) Gecko/20100101 Firefox/26.0"' do
      expect(subject["[wmts][version]"]).to eq("1.0.0")
      expect(subject["[wmts][layer]"]).to eq("grundkarte")
      expect(subject["[wmts][release]"]).to eq("2013")
      expect(subject["[wmts][reference-system]"]).to eq("21781")
      expect(subject["[wmts][zoomlevel]"]).to eq("9")
      expect(subject["[wmts][row]"]).to eq("371")
      expect(subject["[wmts][col]"]).to eq("714")
      expect(subject["[wmts][filetype]"]).to eq("png")
      expect(subject["[wmts][service]"]).to eq("wmts")
      expect(subject["[wmts][input_epsg]"]).to eq("epsg:21781")
      expect(subject["[wmts][input_x]"]).to eq(320516000)
      expect(subject["[wmts][input_y]"]).to eq(-166082000)
      expect(subject["[wmts][input_xy]"]).to eq("320516000,-166082000")
      expect(subject["[wmts][output_epsg]"]).to eq("epsg:4326")
      expect(subject["[wmts][output_xy]"]).to eq("7.438691675813199,-43.38015041464443")
      expect(subject["[wmts][output_x]"]).to eq(7.438691675813199)
      expect(subject["[wmts][output_y]"]).to eq(-43.38015041464443)
    end
  end
  describe "Testing a custom grid sent as parameter to the filter" do
    config <<-CONFIG
      filter {
        grok { match => [ "message", "%{COMBINEDAPACHELOG}" ] }
        grok {
          match => {
            #"request" => "(?<wmts.version>([0-9\.]{5}))\/(?<wmts.layer>([a-z0-9\.-]*))\/default\/(?<wmts.release>([0-9]*))\/(?<wmts.reference-system>([a-z0-9]*))\/(?<wmts.zoomlevel>([0-9]*))\/(?<wmts.row>([0-9]*))\/(?<wmts.col>([0-9]*))\.(?<wmts.filetype>([a-zA-Z]*))"
            "request" => "https?://%{IPORHOST}/%{DATA:[wmts][version]}/%{DATA:[wmts][layer]}/default/%{POSINT:[wmts][release]}/%{DATA:[wmts][reference-system]}/%{POSINT:[wmts][zoomlevel]}/%{POSINT:[wmts][row]}/%{POSINT:[wmts][col]}\.%{WORD:[wmts][filetype]}"
          }
        }
        wmts { 
          epsg_mapping => { 'swissgrid' => 21781 }
          x_origin => 420000
          y_origin => 350000
          tile_width => 256
          tile_height => 256
          resolutions => [ 500, 250, 100, 50, 20, 10, 5, 2.5, 2, 1.5, 1, 0.5, 0.25, 0.1, 0.05 ]
        }
      }
    CONFIG

    sample '1.2.3.4 - - [10/Feb/2014:18:06:12 +0100] "GET http://tile1.example.net/1.0.0/ortho/default/2013/swissgrid/9/374/731.jpeg HTTP/1.1" 200 13872 "http://example.net" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.52 Safari/537.36"' do
      expect(subject["[wmts][version]"]).to eq("1.0.0")
      expect(subject["[wmts][layer]"]).to eq("ortho")
      expect(subject["[wmts][release]"]).to eq("2013")
      expect(subject["[wmts][reference-system]"]).to eq("swissgrid")
      expect(subject["[wmts][zoomlevel]"]).to eq("9")
      expect(subject["[wmts][row]"]).to eq("374")
      expect(subject["[wmts][col]"]).to eq("731")
      expect(subject["[wmts][filetype]"]).to eq("jpeg")
      expect(subject["[wmts][service]"]).to eq("wmts")
      expect(subject["[wmts][input_epsg]"]).to eq("epsg:21781")
      expect(subject["[wmts][input_x]"]).to eq(700896)
      expect(subject["[wmts][input_y]"]).to eq(206192)
      expect(subject["[wmts][input_xy]"]).to eq("700896,206192")
      expect(subject["[wmts][output_epsg]"]).to eq("epsg:4326")
      expect(subject["[wmts][output_xy]"]).to eq("8.765263559441715,46.999112812287045")
      expect(subject["[wmts][output_x]"]).to eq(8.765263559441715)
      expect(subject["[wmts][output_y]"]).to eq(46.999112812287045)
    end
  end
end
