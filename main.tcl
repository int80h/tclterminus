#!/usr/bin/wish8.5
#(C)2010 Charles Valentine <lantern_dev@yahoo.com>

lappend auto_path /usr/local/lib/tclpcap0.1
lappend auto_path [pwd]
package require Pcap
package require packetlib 0.1
package require Tcl 8.5
package require Tk

source ttkui.tcl

set local_time [clock format [clock seconds]]
packetlib::time_every 
set pkt_t_delta 0
set sent_count 0
set recv_count 0


dict set unfiltered 0 null
set app_info [open_default_device]
dict set app_info realtime_display 1
dict set app_info update_proc update_display
set pcapChannel [dict get $app_info pcapChannel]

fileevent $pcapChannel readable [list packetlib::get_packet $pcapChannel [dict get $app_info datalink_type]]
create_ui

