#!/usr/bin/wish8.5
#(C)2010 Charles Valentine

lappend auto_path /usr/local/lib/tclpcap0.1
lappend auto_path [pwd]
package require Pcap
package require packetlib 0.1
package require Tcl 8.5
package require Tk

source ttkui.tcl

set device [pcap::lookupdev]
dict set app_info device $device

set pcapChannel [pcap::pcap_open -nopromisc -filter "tcp" $device]
dict set app_info pcapChannel $pcapChannel

set addrlist [pcap::lookupnet $device]
dict set app_info addrlist $addrlist

fconfigure $pcapChannel -blocking 0 -translation binary
set i 0

set link_type [pcap::datalink $pcapChannel]
if {[lindex $link_type 0] != "DLT_EN10MB"} {
    puts "incompatible link type.  Presently, only Ethernet is supported.\n"
    exit
}

#bind . <Return> {calculate}
puts "chan $pcapChannel"
fileevent $pcapChannel readable [list packetlib::get_packet $pcapChannel]
create_ui $app_info

