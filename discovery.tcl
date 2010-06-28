#!/usr/bin/wish8.5
#(C)2010 Charles Valentine

lappend auto_path /usr/local/lib/tclpcap0.1
lappend auto_path [pwd]
package require Pcap
package require packetlib 0.1
package require Tcl 8.5
package require Tk

proc calculate {} {
    if {[catch { set ::meters [expr {round($::feet*0.3048*10000.0)/10000.0}]}] != 0} {
        set ::meters ""
    }
}

proc get_packet {pcapChannel} {
    puts "get: chan $pcapChannel"
    if {[eof "$pcapChannel"]} {
        set global_eof 1
        return
    }
    set packet [pcap::getPacket $pcapChannel]
    if {[llength $packet] == 0} {
        return
    }
    set pcap_info [packetlib::pcap_header_info [lindex $packet 0]]
    incr i 1

    #TODO: instead of hardcoding for ethernet, write proc to determine type
    set ether_header [string range [lindex $packet 1] 0 13]
    set ether_info [packetlib::ether_header_info [lindex $packet 1]]

    #TODO: instead of hardcoding for ip, write proc to determine type
    set ip_info [packetlib::ip_header_info [string range [lindex $packet 1] 14 end]]

    set network_packet_offset [expr 14 + 4 * [dict get $ip_info header_len]]
    set network_packet [string range [lindex $packet 1] $network_packet_offset end]

    if {[dict get $ip_info protocol] == "6"} {
        set tcp_info [packetlib::tcp_header_info $network_packet]
        set tcp_data [string range $network_packet [expr {"0x[dict get $tcp_info data_offset]" * 4}] end]
    }
    #TODO: assemble _info parts into struct/object and add elaborated packet to app-level tree of packets
}
set device [pcap::lookupdev]
#puts $device

set pcapChannel [pcap::pcap_open -nopromisc -filter "tcp" $device]
#puts $pcapChannel

set addrlist [pcap::lookupnet $device]
#puts $addrlist

fconfigure $pcapChannel -blocking 0 -translation binary
set i 0

set link_type [pcap::datalink $pcapChannel]
if {[lindex $link_type 0] != "DLT_EN10MB"} {
    puts "incompatible link type.  Presently, only Ethernet is supported.\n"
    exit
}

wm title . "Tcl Terminus"
grid [ttk::frame .c -padding "3 3 12 12"] -column 0 -row 0 -sticky nwes
grid columnconfigure . 0 -weight 1
grid rowconfigure . 0 -weight 1

#grid [ttk::entry .c.entry -width 7 -textvariable feet] -column 2 -row 2 -sticky we
grid [ttk::label .c.devlbl -text "Device $device"] -column 1 -row 1 -sticky we
grid [ttk::label .c.pcapchanlbl -text "Channel $pcapChannel"] -column 2 -row 1 -sticky we
grid [ttk::label .c.addrlist -text "addrs: $addrlist"] -column 1 -row 2 -sticky we
#grid [ttk::button .c.calc -text "calculate" -command calculate] -column 3 -row 3 -sticky w

#grid [ttk::label .c.flbl -text "feet"] -column 3 -row 1 -sticky w
#grid [ttk::label .c.islbl -text "is equivalent to"] -column 1 -row 2 -sticky e
#grid [ttk::label .c.mlbl -text "meters"] -column 3 -row 2 -sticky w

foreach w [winfo children .c] {grid configure $w -padx 5 -pady 5}
#focus .c.entry
#bind . <Return> {calculate}
puts "chan $pcapChannel"
#after idle [list get_packet $pcapChannel]
fileevent $pcapChannel readable [list get_packet $pcapChannel]

