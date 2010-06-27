#!/usr/bin/tclsh8.5
#(C)2010 Charles Valentine

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
    dict set ether pretty_src [pretty_mac $src]
    #puts "pretty mac src is [dict get $ether pretty_src]"
    dict set ether dest $dest
    dict set ether pretty_dest [pretty_mac $dest]
    #puts "pretty mac dest is [dict get $ether pretty_dest]"
    dict set ether len $len
    return $ether
}

proc pretty_mac {addr} {
    set pair1 [string range $addr 0 1]
    set pair2 [string range $addr 2 3]
    set pair3 [string range $addr 4 5]
    set pair4 [string range $addr 6 7]
    set pair5 [string range $addr 8 9]
    set pair6 [string range $addr 10 11]
    lappend pairs $pair1 $pair2 $pair3 $pair4 $pair5 $pair6
    set pretty [join $pairs ":"]
    return $pretty
}

proc pretty_ip {addr} {
    foreach octet $addr {
        lappend dec_octets [expr { $octet & 0xff}]
    }
    set pretty [join $dec_octets "."]
    #puts "orig: $addr pretty: $pretty"
    return $pretty
}

proc convert_bit_string {str} {
    # takes big-endian bit string
    set len [string length $str]
    set val 0
    for {set i 0} {$i < 8} {incr i} {
        set c [string index $str $i]
        set pownum [expr $len - 1 - $i]
        set power [expr round(pow(2,$pownum))]
        set val [expr $val + [expr "$c" * "$power"]]
    }
    return $val
}

proc ip_header_info {packet} {
    puts "packet length is [string length $packet]"
    #binary scan $packet ccSuSuB3B11ccSuc4c4 vhl tos total_len id flags fragment_off ttl protocol checksum src dest
    binary scan $packet B8c vhl tos
    #puts "vhl1 $vhl1"
    set version "0000"
    append version [string range $vhl 0 3]
    set version [convert_bit_string $version]
    set header_len "0000"
    append header_len [string range $vhl 4 7]
    set header_len [convert_bit_string $header_len]
    dict set ip version $version
    dict set ip header_len $header_len
    dict set ip tos $tos
    #dict set ip total_len $total_len
    #dict set ip id $id
    #dict set ip flags $flags
    #dict set ip fragment_offset $fragment_off
    #dict set ip ttl $ttl
    #dict set ip protocol $protocol
    dict set ip protocol "6"
    #dict set ip checksum $checksum
    #dict set ip src $src
    #dict set ip pretty_src [pretty_ip $src]
    #dict set ip dest $dest
    #dict set ip pretty_dest [pretty_ip $dest]
    return $ip
}

proc tcp_header_info {tcp_packet} {
    puts "packet: $tcp_packet\nlength: [string length $tcp_packet]"
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

fconfigure $pcapChannel -blocking 0 -translation binary
set i 0

set link_type [pcap::datalink $pcapChannel]
if {[lindex $link_type 0] != "DLT_EN10MB"} {
    puts "incompatible link type.  Presently, only Ethernet is supported.\n"
    exit
}

while {![eof $pcapChannel]} {
    puts "new packet\n"
    set packet [pcap::getPacket $pcapChannel]

    set pcap_info [pcap_header_info [lindex $packet 0]]

    #set pcap_data [lindex $packet 1]
    incr i 1
    #puts "full data:[lindex $packet 1]"
    set ether_header [string range [lindex $packet 1] 0 13]
    set ether_info [ether_header_info [lindex $packet 1]]

    set ip_info [ip_header_info [string range [lindex $packet 1] 14 33]]

    if {[dict get $ip_info protocol] == "6"} {
        set tcp_packet [string range [lindex $packet 1] 34 end]
        #set tcp_info [tcp_header_info $tcp_packet]

        #set tcp_data [string range $tcp_packet [expr {"0x[dict get $tcp_info data_offset]" * 4}] end]
        #puts "src mac=[dict get $ether_info pretty_src] ip addr=[dict get $ip_info pretty_src] tcp port=[dict get $tcp_info source_port]"
        #puts "dest mac=[dict get $ether_info pretty_dest] ip addr=[dict get $ip_info pretty_dest] tcp port=[dict get $tcp_info dest_port]"
        #puts "packet length [string length $packet] header lengths: ether=[dict get $ether_info len]"
        puts "ip header len=[dict get $ip_info header_len]"; # total=[dict get $ip_info total_len] bytes"
        #puts "tcp len 0x[dict get $tcp_info data_offset] words ([expr {[dict get $tcp_info data_offset] * 4}] bytes)"
        puts "ip header: ver [dict get $ip_info version] tos [dict get $ip_info tos]"; # id [dict get $ip_info id] flags [dict get $ip_info flags] fragment offset [dict get $ip_info fragment_offset] ttl [dict get $ip_info ttl] proto [dict get $ip_info protocol] checksum [dict get $ip_info checksum]"
        #puts "tcp header: seq #[dict get $tcp_info seq_num] ack #[dict get $tcp_info ack_num]  options [dict get $tcp_info options] ([dict get $tcp_info option_line]) window size [dict get $tcp_info window_size] checksum [dict get $tcp_info checksum] urgent ptr [dict get $tcp_info urgent_ptr]\n"
        #puts "tcp data: $tcp_data"
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
