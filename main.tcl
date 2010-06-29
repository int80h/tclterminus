#!/usr/bin/wish8.5
#(C)2010 Charles Valentine <lantern_dev@yahoo.com>

lappend auto_path /usr/local/lib/tclpcap0.1
lappend auto_path [pwd]
package require Pcap
package require packetlib 0.1
package require Tcl 8.5
package require Tk

source ttkui.tcl

set app_info [open_default_device]
set pcapChannel [dict get $app_info pcapChannel]

fileevent $pcapChannel readable [list packetlib::get_packet $pcapChannel [dict get $app_info datalink_type]]
create_ui $app_info

