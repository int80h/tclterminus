#!/usr/bin/tclsh8.5
#(C)2010 Charles Valentine
package provide packetlib 0.1

#TODO: packetlib should only export conversion and get_packet fns.  *_header_info should be internal, called by get_packet.
namespace eval ::packetlib {
    namespace export pcap_header_info ether_header_info tcp_header_info pretty_mac pretty_ip convert_bit_string ip_header_info get_packet every
}

lappend auto_path /usr/local/lib/tclpcap0.1
package require Pcap


#from http://wiki.tcl.tk/9299
proc ::packetlib::time_every {} {
    global local_time

    set local_time [clock format [clock seconds]]
    after 1000 [info level 0]
}

proc ::packetlib::pcap_header_info {pcap_header} {
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

proc ::packetlib::scan_tcp_header {tcp_packet} {
    puts "tcp packet: $tcp_packet\nlength: [string length $tcp_packet]"
    binary scan $tcp_packet SuSuIuIuB16SuSuSu source_port dest_port seq_num ack_num data_offset_tcp_options window_size checksum urgent_ptr

    dict set tcp source_port $source_port
    dict set tcp dest_port $dest_port
    dict set tcp seq_num $seq_num
    dict set tcp ack_num $ack_num
    dict set tcp window_size $window_size
    dict set tcp checksum $checksum
    dict set tcp urgent_ptr $urgent_ptr

    set data_offset "0000"
    append data_offset [string range $data_offset_tcp_options 0 3]
    set data_offset [convert_bit_string $data_offset]
    # data_offset is length of tcp header, which can be between 20 and 60 bytes.
    #expressed in 32-bit words, so value is between 0x05 and 0x0e.  multiply by 4 to get number of bytes.
    dict set tcp data_offset [expr {"$data_offset" * 4}]
    set tcp_options [string range $data_offset_tcp_options 8 end]; # bits 4,5,6,7 of combined field are reserved

    dict set tcp options $tcp_options
    set option_line ""
    #the options were read MSB first so end with fin flag
    dict set tcp opt fin [string index $tcp_options 7]
    if {[dict get $tcp opt fin] == "1"} {
        append option_line " FIN"
    }
    dict set tcp opt syn [string index $tcp_options 6]
    if {[dict get $tcp opt syn] == "1"} {
        append option_line " SYN"
    }
    dict set tcp opt rst [string index $tcp_options 5]
    if {[dict get $tcp opt rst] == "1"} {
        append option_line " RST"
    }
    dict set tcp opt psh [string index $tcp_options 4]
    if {[dict get $tcp opt psh] == "1"} {
        append option_line " PSH"
    }
    dict set tcp opt ack [string index $tcp_options 3]
    if {[dict get $tcp opt ack] == "1"} {
        append option_line " ACK"
    }
    dict set tcp opt urg [string index $tcp_options 2]
    if {[dict get $tcp opt urg] == "1"} {
        append option_line " URG"
    }
    dict set tcp opt ece [string index $tcp_options 1]
    if {[dict get $tcp opt ece] == "1"} {
        append option_line " ECE"
    }
    dict set tcp opt cwr [string index $tcp_options 0]
    if {[dict get $tcp opt cwr] == "1"} {
        append option_line " CWR"
    }
    dict set tcp option_line $option_line

    return $tcp
}

proc ::packetlib::pretty_mac {addr} {
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

proc ::packetlib::pretty_ip {addr} {
    foreach octet $addr {
        lappend dec_octets [expr { $octet & 0xff}]
    }
    set pretty [join $dec_octets "."]
    #puts "orig: $addr pretty: $pretty"
    return $pretty
}

proc ::packetlib::convert_bit_string {str} {
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

proc ::packetlib::scan_ip_header {packet} {
    puts "packet length is [string length $packet]"
    #binary scan $packet ccSuSuB3B11ccSuc4c4 vhl tos total_len id flags fragment_off ttl protocol checksum src dest
    binary scan $packet B8cSuSuB16ccSuc4c4 vhl tos total_len id flags_off ttl protocol checksum src dest

    set version "0000"
    append version [string range $vhl 0 3]
    set version [convert_bit_string $version]

    set header_len "0000"
    append header_len [string range $vhl 4 7]
    set header_len [convert_bit_string $header_len]

    dict set ip version $version
    dict set ip header_len $header_len

    #TODO: extract tos fields
    dict set ip tos $tos
    dict set ip total_len $total_len
    dict set ip id $id

    #TODO: separate flags out from fragment offset, both in B16 -> flags_off.
    dict set ip flags $flags_off
    dict set ip fragment_offset $flags_off

    dict set ip ttl $ttl
    dict set ip protocol $protocol
    dict set ip checksum $checksum; # calculated over the IP header only

    dict set ip src $src
    dict set ip pretty_src [pretty_ip $src]
    dict set ip dest $dest
    dict set ip pretty_dest [pretty_ip $dest]
    dict set ip display update_ipv4_display

    return $ip
}

proc ::packetlib::scan_ether_header {packet} {
    #dict set link_h header [string range [lindex $packet 1] 0 13]
    binary scan $packet H12H12Su src dest len
    dict set link_h src $src
    dict set link_h pretty_src [pretty_mac $src]
    dict set link_h dest $dest
    dict set link_h pretty_dest [pretty_mac $dest]
    # len also seems to serve as type
    dict set link_h len $len

    # type and header_len will be standard for link_h types.  header_len should be in bytes.
    dict set link_h header_len $len
    
    # set to name of proc that will update ether display fields
    dict set link_h display update_ether_display
    return $link_h
}

proc ::packetlib::type_link_header {packet device_type} {
    if {$device_type == "DLT_EN10MB Ethernet"} {
        return [scan_ether_header $packet]
    } else {
        puts "$device_type is an unimplemented device/link type."
        exit
    }
}

proc ::packetlib::type_trans_header {packet} {
    return [scan_ip_header $packet]
}

proc ::packetlib::type_net_header {packet protocol} {
    if {$protocol == 6} {
        return [scan_tcp_header $packet]
    } else {
        puts "$protocol is an unimplemented network protocol type."
        exit
    }
}

proc ::packetlib::get_packet {pcapChannel device_type} {
    global unfiltered
    # returns packet_id, 0 length, or -1 eof
    puts "get: chan $pcapChannel"
    if {[eof "$pcapChannel"]} {
        set global_eof 1
        return -1
    }
    set pcap_packet [pcap::getPacket $pcapChannel]
    if {[llength $pcap_packet] == 0} {
        return 0
    }

    dict set packet raw $pcap_packet 

    set pcap_info [packetlib::pcap_header_info [lindex $pcap_packet 0]]
    dict set packet pcap $pcap_info
    incr i 1

    #TODO: after link_h.header_len is converted to bytes, should strip that # of bytes from work copy of packet
    set link_h [type_link_header $pcap_packet $device_type]
    dict set packet link $link_h

    set trans_h [type_trans_header [string range [lindex $pcap_packet 1] 14 end]]
    dict set packet trans $trans_h

    set network_packet_offset [expr 14 + 4 * [dict get $trans_h header_len]]
    set network_packet [string range [lindex $pcap_packet 1] $network_packet_offset end]
    set net_h [type_net_header [string range [lindex $pcap_packet 1] 14 end] [dict get $trans_h protocol]]
    dict set packet net $net_h

    set data [string range $network_packet [expr {"0x[dict get $net_h data_offset]" * 4}] end]
    dict set packet data $data

    #puts "src mac=[dict get $link_h pretty_src] ip addr=[dict get $trans_h pretty_src] tcp port=[dict get $net_h source_port]"
    #puts "dest mac=[dict get $link_h pretty_dest] ip addr=[dict get $trans_h pretty_dest] tcp port=[dict get $net_h dest_port]"
    #puts "packet length [string length $pcap_packet] header lengths: ether=[dict get $link_h len]"
    #puts "ip header len=[dict get $trans_h header_len] words ([expr 4 * [dict get $trans_h header_len]] bytes) total=[dict get $trans_h total_len] bytes"
    #puts "tcp len 0x[dict get $net_h data_offset] words ([expr {[dict get $net_h data_offset] * 4}] bytes)"
    #puts "ip header: ver [dict get $trans_h version] tos [dict get $trans_h tos] id [dict get $trans_h id]"; # flags [dict get $trans_h flags] fragment offset [dict get $trans_h fragment_offset]"
    #puts "ttl [dict get $trans_h ttl] proto [dict get $trans_h protocol] checksum [dict get $trans_h checksum]"
    #puts "tcp header: seq #[dict get $net_h seq_num] ack #[dict get $net_h ack_num]  options [dict get $net_h options] ([dict get $net_h option_line]) window size [dict get $net_h window_size] checksum [dict get $net_h checksum] urgent ptr [dict get $net_h urgent_ptr]\n"

    dict set packet packet_id 37
    dict set packet len [string length [dict get $packet raw]]
    set packet_id [dict get $packet packet_id]
    puts "id [dict get $packet packet_id]"
    puts "full: [dict get $packet link]"
    dict set unfiltered $packet_id $packet
    process_packet $packet_id
}

proc ::packetlib::process_packet {packet_id} {
    global app_info

    [dict get $app_info update_proc] $packet_id

}
