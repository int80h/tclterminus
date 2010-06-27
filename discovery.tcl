#!/usr/bin/tclsh8.5
#(C)2010 Charles Valentine

lappend auto_path /usr/local/lib/tclpcap0.1
lappend auto_path [pwd]
package require Pcap
package require packetlib 0.1

set device [pcap::lookupdev]
puts $device

set pcapChannel [pcap::pcap_open -nopromisc -filter "tcp" $device]
puts $pcapChannel

set addrlist [pcap::lookupnet $device]
puts $addrlist

fconfigure $pcapChannel -blocking 0 -translation binary
set i 0

set link_type [pcap::datalink $pcapChannel]
if {[lindex $link_type 0] != "DLT_EN10MB"} {
    puts "incompatible link type.  Presently, only Ethernet is supported.\n"
    exit
}

while {![eof $pcapChannel]} {
    set packet [pcap::getPacket $pcapChannel]

    set pcap_info [packetlib::pcap_header_info [lindex $packet 0]]

    incr i 1
    puts "new packet $i: payload len is [string length $packet]\n"
    set ether_header [string range [lindex $packet 1] 0 13]
    set ether_info [packetlib::ether_header_info [lindex $packet 1]]

    set ip_info [packetlib::ip_header_info [string range [lindex $packet 1] 14 end]]
    set network_packet_offset [expr 14 + 4 * [dict get $ip_info header_len]]
    set network_packet [string range [lindex $packet 1] $network_packet_offset end]

    if {[dict get $ip_info protocol] == "6"} {
        puts "TCP protocol"
        set tcp_info [packetlib::tcp_header_info $network_packet]

        set tcp_data [string range $network_packet [expr {"0x[dict get $tcp_info data_offset]" * 4}] end]
        puts "src mac=[dict get $ether_info pretty_src] ip addr=[dict get $ip_info pretty_src] tcp port=[dict get $tcp_info source_port]"
        puts "dest mac=[dict get $ether_info pretty_dest] ip addr=[dict get $ip_info pretty_dest] tcp port=[dict get $tcp_info dest_port]"
        puts "packet length [string length $packet] header lengths: ether=[dict get $ether_info len]"
        puts "ip header len=[dict get $ip_info header_len] words ([expr 4 * [dict get $ip_info header_len]] bytes) total=[dict get $ip_info total_len] bytes"
        puts "tcp len 0x[dict get $tcp_info data_offset] words ([expr {[dict get $tcp_info data_offset] * 4}] bytes)"
        puts "ip header: ver [dict get $ip_info version] tos [dict get $ip_info tos] id [dict get $ip_info id]"; # flags [dict get $ip_info flags] fragment offset [dict get $ip_info fragment_offset]"
        puts "ttl [dict get $ip_info ttl] proto [dict get $ip_info protocol] checksum [dict get $ip_info checksum]"
        puts "tcp header: seq #[dict get $tcp_info seq_num] ack #[dict get $tcp_info ack_num]  options [dict get $tcp_info options] ([dict get $tcp_info option_line]) window size [dict get $tcp_info window_size] checksum [dict get $tcp_info checksum] urgent ptr [dict get $tcp_info urgent_ptr]\n"
        #puts "tcp data: $tcp_data"
    } elseif {[dict get $ip_info protocol] == "1"} {
        puts "ICMP"
        #binary scan ccSua* type code checksum message
    } elseif {[dict get $ip_info protocol] == "2"} {
        puts "IGMP"
    } elseif {[dict get $ip_info protocol] == "17"} {
        puts "UDP"
    } elseif {[dict get $ip_info protocol] == "89"} {
        puts "OSPF"
    } elseif {[dict get $ip_info protocol] == "132"} {
        puts "SCTP"
    } else {
        puts "ip protocol number [dict get $ip_info protocol] not supported."
    }
}

#
#set device fi.cap
#
#proc print_packet {pcapChannel} {
#    global count$pcapChannel
#    if {[set count$pcapChannel] == 20} {
#        global closeChannel$pcapChannel
#        set closeChannel$pcapChannel 1
#        return
#    }
#    incr count$pcapChannel 
#    set packet [pcap::getPacket $pcapChannel]
#    pcap::printPacket $packet
#}
#
#set count$p 0
#fconfigure $p -blocking 0
#fconfigure $p -savefile foo.sav
#pcap::savefile $p on
#puts "$p options are \"[fconfigure $p]\""
#fileevent $p readable "print_packet $p"
#vwait closeChannel$p
#close $p
