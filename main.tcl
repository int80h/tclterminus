#!/usr/bin/wish8.5
#(C)2010 Charles Valentine <lantern_dev@yahoo.com>

lappend auto_path /usr/local/lib/tclpcap0.1
lappend auto_path [pwd]

package require Pcap
package require packetlib 0.1
package require Tcl 8.5
package require Tk
package require cmdline

source ttkui.tcl

set filename ""

set optlist {
    {h      "help"}
    {v      "version"}
    {i.arg  "read pcap file"}
}

puts "argv: $argv"
array set opts [cmdline::getoptions argv $optlist]
#puts "opts: $opts"
if { $opts(h) } {
    puts [cmdline::usage]
    exit
} elseif { $opts(v) } {
    puts "tclterminus version 0.1"
    exit
} elseif { $opts(i) != "" } {
    set filename $opts(i)
    puts "got -i, filename is $filename"
}

if {$filename == ""} {
    set app_info [open_default_device]
} else {
    set app_info [open_pcap_file $filename]
}

set local_time [clock format [clock seconds]]
packetlib::time_every 
set pkt_t_delta 0
set sent_count 0
set recv_count 0

dict set unfiltered 0 null
dict set app_info realtime_display 1
dict set app_info update_proc update_display
set pcapChannel [dict get $app_info pcapChannel]

fileevent $pcapChannel readable [list packetlib::get_packet $pcapChannel [dict get $app_info datalink_type]]
create_ui

