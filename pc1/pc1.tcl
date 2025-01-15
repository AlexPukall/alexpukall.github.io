
#
# This file converts PC1 cipher into TCL
# (c) Alexander Pukall
#
# It encrypt/decrypt test strings 
#
# Programmer:  huey_jiang@yahoo.com
#
# July 26, 2003
#
# 
#
#  USAGE EXAMPLE:  % set encrypted [pc1_encrypt_string "Hello the world" "passwd"]
#                  % puts $encrypted      ----> here you got encrypted string "poacdcogjegmojplpoblmegnjhedkk"
#				   % set decryptd [pc1_decrypt_string $encrypted "passwd" ]
#				   % puts $decrypted      ----> here you got "Hello the world" back
#

set ax 0
set bx 0
set cx 0
set dx 0
set si 0
set tmp 0
set x1a2 0
set res 0
set i 0
set inter 0
set cfc 0
set cfd 0
set compte 0
set c 0
set cle "123456abcdefghijklmnopqrstuvwxyz"
set x1a0(0) 0
set x1a0(1) 0
set x1a0(2) 0
set x1a0(3) 0
set x1a0(4) 0

proc fin {} {
global ax bx cx dx si tmp x1a2 x1a0 res i inter cfc cfd compte cle
global c c1 count d e

	set cle "123456abcdefghijklmnopqrstuvwxyz"

	set ax 0
	set bx 0
	set cx 0
	set dx 0
	set si 0
	set tmp 0
	set x1a2 0
	set x1a0(0) 0
	set x1a0(1) 0
	set x1a0(2) 0
	set x1a0(3) 0
	set x1a0(4) 0
	set res 0
	set i 0
	set inter 0
	set cfc 0
	set cfd 0
	set compte 0
	set c 0
	return 0
}
proc assemble {} {
global ax bx cx dx si tmp x1a2 x1a0 res i inter cfc cfd compte cle
global c c1 count d e ascii_table

	set cool [ascii2value [string index $cle 0 ]]
	set kool [ascii2value [string index $cle 1 ]]
	set xxx [expr $cool * 256 + $kool ]
	set x1a0(0) $xxx 
	code
	set inter $res
	
	set cool [ascii2value [string index $cle 2 ]]
	set kool [ascii2value [string index $cle 3 ]]
	set xxx [expr $x1a0(0) ^ [expr $cool * 256 + $kool ]]
	set x1a0(1) $xxx 
	code
	set inter [expr $inter ^ $res]	

	set cool [ascii2value [string index $cle 4 ]]
	set kool [ascii2value [string index $cle 5 ]]
	set xxx [expr $x1a0(1) ^ [expr $cool * 256 + $kool ]]
	set x1a0(2) $xxx 
	code
	set inter [expr $inter ^ $res]	

	set cool [ascii2value [string index $cle 6 ]]
	set kool [ascii2value [string index $cle 7 ]]
	set xxx [expr $x1a0(2) ^ [expr $cool * 256 + $kool ]]
	set x1a0(3) $xxx 
	code
	set inter [expr $inter ^ $res]	

	set cool [ascii2value [string index $cle 8 ]]
	set kool [ascii2value [string index $cle 9 ]]
	set xxx [expr $x1a0(3) ^ [expr $cool * 256 + $kool ]]
	set x1a0(4) $xxx 
	code
	set inter [expr $inter ^ $res]	

	set cool [ascii2value [string index $cle 10 ]]
	set kool [ascii2value [string index $cle 11 ]]
	set xxx [expr $x1a0(4) ^ [expr $cool * 256 + $kool ]]
	set x1a0(5) $xxx 
	code
	set inter [expr $inter ^ $res]	
	
	set cool [ascii2value [string index $cle 12 ]]
	set kool [ascii2value [string index $cle 13 ]]
	set xxx [expr $x1a0(5) ^ [expr $cool * 256 + $kool ]]
	set x1a0(6) $xxx 
	code
	set inter [expr $inter ^ $res]	
	
	set cool [ascii2value [string index $cle 14 ]]
	set kool [ascii2value [string index $cle 15 ]]
	set xxx [expr $x1a0(6) ^ [expr $cool * 256 + $kool ]]
	set x1a0(7) $xxx 
	code
	set inter [expr $inter ^ $res]	
	
	set cool [ascii2value [string index $cle 16 ]]
	set kool [ascii2value [string index $cle 17 ]]
	set xxx [expr $x1a0(7) ^ [expr $cool * 256 + $kool ]]
	set x1a0(8) $xxx 
	code
	set inter [expr $inter ^ $res]	
	
	set cool [ascii2value [string index $cle 18 ]]
	set kool [ascii2value [string index $cle 19 ]]
	set xxx [expr $x1a0(8) ^ [expr $cool * 256 + $kool ]]
	set x1a0(9) $xxx 
	code
	set inter [expr $inter ^ $res]	
	
	set cool [ascii2value [string index $cle 20 ]]
	set kool [ascii2value [string index $cle 21 ]]
	set xxx [expr $x1a0(9) ^ [expr $cool * 256 + $kool ]]
	set x1a0(10) $xxx 
	code
	set inter [expr $inter ^ $res]	
		
	set cool [ascii2value [string index $cle 22 ]]
	set kool [ascii2value [string index $cle 23 ]]
	set xxx [expr $x1a0(10) ^ [expr $cool * 256 + $kool ]]
	set x1a0(11) $xxx 
	code
	set inter [expr $inter ^ $res]	
	
	set cool [ascii2value [string index $cle 24 ]]
	set kool [ascii2value [string index $cle 25 ]]
	set xxx [expr $x1a0(11) ^ [expr $cool * 256 + $kool ]]
	set x1a0(12) $xxx 
	code
	set inter [expr $inter ^ $res]	
	
	set cool [ascii2value [string index $cle 26 ]]
	set kool [ascii2value [string index $cle 27 ]]
	set xxx [expr $x1a0(12) ^ [expr $cool * 256 + $kool ]]
	set x1a0(13) $xxx 
	code
	set inter [expr $inter ^ $res]	
	
	set cool [ascii2value [string index $cle 28 ]]
	set kool [ascii2value [string index $cle 29 ]]
	set xxx [expr $x1a0(13) ^ [expr $cool * 256 + $kool ]]
	set x1a0(14) $xxx 
	code
	set inter [expr $inter ^ $res]	
		
	set cool [ascii2value [string index $cle 30 ]]
	set kool [ascii2value [string index $cle 31 ]]
	set xxx [expr $x1a0(14) ^ [expr $cool * 256 + $kool ]]
	set x1a0(15) $xxx 
	code
	set inter [expr $inter ^ $res]	

	set i 0
	
	return 0	
}
proc code {} {
	global ax bx cx dx si tmp x1a2 x1a0 res i inter cfc cfd 

	set dx [expr $x1a2 + $i ]
	set ax $x1a0($i)
	set cx 0x015a
	set bx 0x4e35

	set tmp $ax
	set ax $si
	set si $tmp	
	
	set tmp $ax
	set ax $dx
	set dx $tmp

	if {$ax != 0 } {
		set ax [make_16bits [expr $ax * $bx ]	]
	}

	set tmp $ax
	set ax $cx
	set cx $tmp

	if { $ax != 0 } {
		set ax [make_16bits [expr $ax * $si ]]
		set cx [make_16bits [expr $ax + $cx ]	]
	}

	set tmp $ax
	set ax $si
	set si $tmp
	set ax [make_16bits [expr $ax * $bx ]]
	set dx [make_16bits [expr $cx + $dx ]]
	
	incr ax
	
	set x1a2 $dx
	set x1a0($i) $ax 
	
	set res [expr $ax ^ $dx ]
	incr i

	return 0
}

proc make_16bits { num } {

	set xnum [format "%x" $num ]
	set len [string length $xnum ]
	set pos [expr $len - 4 ]
	set xnum16 [string range $xnum $pos $len ]
	return "0x$xnum16"	
}
proc pc1_encrypt_string {instr passwd } {
	global ax bx cx dx si tmp x1a2 x1a0 res i inter cfc cfd compte cle
	global c c1 count d e 
	set outstr ""
	
	set si 0
	set x1a2 0
	set i 0
	fin
	
	set cle [string_replace_string $cle $passwd 1 ]

	set length [string length $instr]
		
	for {set j 0 } { $j < $length} {incr j} {
		
		set c [string index $instr $j]
		set aaa [ascii2value $c ]
		assemble

		set cfc	[expr $inter >> 8 ]
		set cfd [expr $inter & 255 ]
		#
		# K-zone below
		#

		for {set compte 0 } {$compte <= 31} {incr compte } {
			set ccc [string index $cle $compte ]
			set xxx [expr $ccc ^ $aaa ]	
			set cle [string_replace_char $cle $xxx $compte ]
		}
		
		set aaa [expr $aaa ^ [expr $cfc ^ $cfd ]]

		set d [expr $aaa >> 4 ]
		set e [expr $aaa & 15 ]
		
		set dd [value2ascii [expr 0x61 + $d ]]
		set ee [value2ascii [expr 0x61 + $e ]]
		
		set outstr "$outstr$dd$ee"
	}
	return $outstr
}

proc pc1_decrypt_string { instr passwd } {
	global ax bx cx dx si tmp x1a2 x1a0 res i inter cfc cfd compte cle
	global c c1 count d e 
	
	set outstr ""
	set si 0
	set x1a2 0
	set i 0
	fin

	set cle [string_replace_string $cle $passwd 1 ]

	set length [string length $instr]
	set length [expr $length / 2 ]
	
	for {set j 0 } { $j < $length} {incr j} {
		
		set k [expr $j * 2 ]
		set kk [expr $k + 1 ]
		
		set d [string index $instr $k]
		set e [string index $instr $kk ]
		
		set dd [ascii2value $d ]
		set ee [ascii2value $e ]
	
		set dd [expr $dd - 0x61 ]
		set dd [expr $dd << 4 ]
		
		set ee [expr $ee - 0x61 ]
		set cc [expr $dd + $ee ]

		assemble

		set cfc [expr $inter >> 8 ]
		set cfd [expr $inter & 255 ]

		set yyy [expr $cfc ^ $cfd ]
		set cc [expr $cc ^ $yyy]

		for {set compte 0 } {$compte <= 31 } {incr compte} {
			set ccc [string index $cle $compte ]
			set xxx [expr $ccc ^ $cc ]

			set cle [string_replace_char $cle [expr $ccc ^ $cc ] $compte]
			
		}
		set cc [value2ascii $cc]
		set outstr "$outstr$cc"
	}
	return $outstr
}


proc ascii2value { c } {
	scan $c %c n
	return [expr $n ]	
}

proc value2ascii { v } {
	return [ format %c $v ]
}

proc string_replace_char {astring achar pos } {
	
	set len [string length $astring ]
	if { $pos < $len } {
		if { $pos == 0 } {
			set tail [string range $astring 1 $len ]
			set result "$achar$tail"
			return $result	
		}
		if {$pos == $len } {
			incr len -1
			set head [string range $astring 0 $len ]
			set result "$head$achar"
			return $result	
		}
		set left [incr pos -1 ]
		set right [incr pos 2 ]
		set head [string range $astring 0 $left]
		set tail [string range $astring $right $len]
		set result "$head$achar$tail"
		return $result
	} else {
		return "Error"	
	}	
}
proc string_replace_string {astring str pos } {
	
	set len [string length $astring ]
	set leny [string length $str ]
	set diff [expr $len - $leny]
	if { $pos < $diff } {
		if { $pos == 0 } {
			set right [expr $pos + $leny]
			set tail [string range $astring $right $len]
			set result "$str$tail"
			return $result	
		} else {
			set right [expr $pos + $leny]
			set left [incr pos -1 ]
			set head [string range $astring 0 $left]
			set tail [string range $astring $right $len]
			set result "$head$str$tail"
			return $result
		}
	} else {
		return "Error: string replacing"	
	}	
}

set foo [pc1_encrypt_string "Hello the world" "passwd"]
puts $foo
set bar [pc1_decrypt_string $foo "passwd"]
puts $bar