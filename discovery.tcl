#!/usr/bin/tclsh8.5
lappend auto_path /usr/local/lib/tclpcap0.1
package require Pcap

proc pcap_header_info {pcap_header} {
    scan $pcap_header "%s %s %s" timestamp caplen len
    if {$caplen != $len} {
        puts "partial pcap packet: timestamp $timestamp caplen $caplen len $len\n"
    } else {
        puts "timestamp: $timestamp length=$len\n"
    }

    dict set info timestamp $timestamp
    dict set info caplen $caplen
    dict set info len $len
    return $info
}

proc ether_header_info {packet} {
    binary scan $packet H12H12Su src dest len
    dict set ether src $src
    dict set ether dest $dest
    dict set ether len $len
    return $ether
}

proc ip_header_info {packet} {
    binary scan $packet b4b4cuSub3b11cucuSuIuIu version len tos id flags fragment_off ttl protocol checksum src dest
    dict set ip version $version
    dict set ip len $len
    dict set ip tos $tos
    dict set ip id $id
    dict set ip flags $flags
    dict set ip fragment_offset $fragment_off
    dict set ip ttl $ttl
    dict set ip protocol $protocol
    dict set ip checksum $checksum
    dict set ip src $src
    dict set ip dest $dest
    return $ip
}

proc tcp_header_info {tcp_packet} {
    binary scan $tcp_packet SuSuIuIuh2b8IuIuIu source_port dest_port seq_num ack_num data_offset tcp_options window_size checksum urgent_ptr

    dict set tcp source_port $source_port
    dict set tcp dest_port $dest_port
    dict set tcp seq_num $seq_num
    dict set tcp ack_num $ack_num
    dict set tcp window_size $window_size
    dict set tcp checksum $checksum
    dict set tcp urgent_ptr $urgent_ptr

    # data_offset is length of tcp header, which can be between 20 and 60 bytes.
    #expressed in 32-bit words, so value is between 0x05 and 0x0e.  multiply by 4 to get number of bytes.
    dict set tcp data_offset [expr {"0x$data_offset" * 4}]

    dict set tcp options $tcp_options
    set option_line ""
    #the options were read LSB first (using h2 as scan format), so start with fin flag
    dict set tcp opt fin [string index $tcp_options 0]
    if {[dict get $tcp opt fin] == "1"} {
        append option_line " FIN"
    }
    dict set tcp opt syn [string index $tcp_options 1]
    if {[dict get $tcp opt syn] == "1"} {
        append option_line " SYN"
    }
    dict set tcp opt rst [string index $tcp_options 2]
    if {[dict get $tcp opt rst] == "1"} {
        append option_line " RST"
    }
    dict set tcp opt psh [string index $tcp_options 3]
    if {[dict get $tcp opt psh] == "1"} {
        append option_line " PSH"
    }
    dict set tcp opt ack [string index $tcp_options 4]
    if {[dict get $tcp opt ack] == "1"} {
        append option_line " ACK"
    }
    dict set tcp opt urg [string index $tcp_options 5]
    if {[dict get $tcp opt urg] == "1"} {
        append option_line " URG"
    }
    dict set tcp opt ece [string index $tcp_options 6]
    if {[dict get $tcp opt ece] == "1"} {
        append option_line " ECE"
    }
    dict set tcp opt cwr [string index $tcp_options 7]
    if {[dict get $tcp opt cwr] == "1"} {
        append option_line " CWR"
    }
    dict set tcp option_line $option_line

    return $tcp
}

set device [pcap::lookupdev]
puts $device

set pcapChannel [pcap::pcap_open -nopromisc -filter "tcp" $device]
puts $pcapChannel

set addrlist [pcap::lookupnet $device]
puts $addrlist

fconfigure $pcapChannel -blocking 0
set i 0

set link_type [pcap::datalink $pcapChannel]
if {[lindex $link_type 0] != "DLT_EN10MB"} {
    puts "incompatible link type.  Presently, only Ethernet is supported.\n"
    exit
}

while {![eof $pcapChannel]} {
    set packet [pcap::getPacket $pcapChannel]

    set pcap_info [pcap_header_info [lindex $packet 0]]

    #set pcap_data [lindex $packet 1]
    incr i 1
    #puts "full data:[lindex $packet 1]"
    set ether_header [string range [lindex $packet 1] 0 14]
    set ether_info [ether_header_info [lindex $packet 1]]

    set ip_info [ip_header_info [string range [lindex $packet 1] 14 34]]

    if {[dict get $ip_info protocol] == "6"} {
        set tcp_packet [string range [lindex $packet 1] 34 end]
        set tcp_info [tcp_header_info $tcp_packet]

        set tcp_data [string range $tcp_packet [expr {"0x[dict get $tcp_info data_offset]" * 4}] end]
        puts "src mac=[dict get $ether_info src] ip addr=[dict get $ip_info src] tcp port=[dict get $tcp_info source_port]"
        puts "dest mac=[dict get $ether_info dest] ip addr=[dict get $ip_info dest] tcp port=[dict get $tcp_info dest_port]"
        puts "header lengths: ether=[dict get $ether_info len] ip=[dict get $ip_info len] len 0x[dict get $tcp_info data_offset] words ([expr {[dict get $tcp_info data_offset] * 4}] bytes)"
        puts "ip header: ver [dict get $ip_info version] tos [dict get $ip_info tos] id [dict get $ip_info id] flags [dict get $ip_info flags] fragment offset [dict get $ip_info fragment_offset] ttl [dict get $ip_info ttl] checksum [dict get $ip_info checksum]"
        puts "tcp header: seq #[dict get $tcp_info seq_num] ack #[dict get $tcp_info ack_num]  options [dict get $tcp_info options] ([dict get $tcp_info option_line]) window size [dict get $tcp_info window_size] checksum [dict get $tcp_info checksum] urgent ptr [dict get $tcp_info urgent_ptr]\n"
        puts "tcp data: $tcp_data"
    } else {
        puts "protocol not supported.  was [dict get $ip_info protocol], expected 6 (TCP)."
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
