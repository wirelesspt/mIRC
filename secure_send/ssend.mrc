#  http://forums.mirc.com/ubbthreads.php/topics/240129/Secure_DCC_File_Transfers_aka_#Post240129

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;                    Mirc SSL DCC Gets Script By Sanchez 2012              ;
;  passive gets not working since you cant /socklisten via ssl             ;
;  speed is limited to around 100kb/s give or take due slow mirc sockets   ;
;  no resume support currently, since its just a PoC                       ;
;  Trigger: DCC SSEND filename ip port filesize                            ;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

ctcp ^*:DCC SSEND*:{

  ; load settings + data
  ; change your dir.
  set %ssldir c:\downloads\
  var %filename = $3
  var %ip = $longip($4)
  var %remoteport = $5
  var %filesize = $6
  var %win = $+(@,%filename)
  var %sn = dcc. $+ %filename

  ; check user against your trusted dcc user list
  var %i = 1
  while ($trust(%i)) {
    if ($v1 iswm $fulladdress)  break
    inc %i
  }
  if ( !$trust(%i) ) {
    echo The user $fulladdress was trying to send you %filename $+ , but he doesnt match your trusted dcc user list. 
    return
  }


  ; check if already running or file complete
  if ($sock(%sn)) {
    echo Transfer %filename still running. Aborting.
    return
  }
  else if ( $file($+(%ssldir,%filename)).size == %filesize ) {
    echo Transfer already complete. Aborting.
    return
  }

  ; connect to remote host and pass arguments  
  /sockopen -e %sn %ip %remoteport
  sockmark %sn $+(%filename,$chr(9),$nick,$chr(9),$ctime,$chr(9),%filesize,$chr(9),0)

  ; open transfer window
  if (!$window(%win)) /window %win
  else {
    /window -c %win
    /window %win
  }
  /aline %win Starting transfer...
  haltdef
}
on *:sockclose:dcc.*: {

  var %sn = $sockname
  var %sm = $sock(%sn).mark
  var %filename = $strip($gettok(%sm,1,9),burc)
  var %win = $+(@,%filename)
  var %nick = $gettok(%sm,2,9)
  var %filesize = $gettok(%sm,4,9)
  var %size = $gettok(%sm,5,9)


  if  (%filesize != %size) {
    echo DOWNLOAD: %filename from %nick incomplete.
    if ($window(%win)) /aline %win %filename from %nick incomplete.
  }
}

on *:sockopen:dcc.*:sockwrite -nt $sockname 0
on *:sockread:dcc.*: {

  var %sn = $sockname
  var %sm = $sock(%sn).mark
  var %filename = $strip($gettok(%sm,1,9),burc)
  var %nick = $gettok(%sm,2,9)
  var %time = $gettok(%sm,3,9)
  var %filesize = $gettok(%sm,4,9)
  var %win = $+(@,%filename)

  var %sockbr = 0
  var %size = $gettok(%sm,5,9)
  if ($sockerr > 0) return


  :nextread
  sockread 16384 &x

  var %readbytes = $sockbr
  inc %size %readbytes

  ; no new data
  if (%readbytes == 0) {

    ;TODO: send constant acks and check if its gonna be any faster
    ;if ( %size >= 65536) {
    ;sockwrite -nt $sockname $base(%deltasize, 10, 16)
    ;}

    /rline %win 1 %filename - %size from %filesize downloaded $+ $round($calc( %size * 100 / %filesize),0) $%), at $round($calc( %size / (($ctime - %time) * 1000) ),2) kb/s.
    return
  }
  else {
    ; append data to file
    /bwrite %ssldir $+ %filename -1 &x
  }

  ; update current filesize
  sockmark $sockname $puttok(%sm,%size,5,9)

  ; file complete, send ack and have the remote host close the socket
  if  (%filesize == %size) {
    echo DOWNLOAD: %filename from %nick completed after $duration($calc($ctime - %time))
    /rline %win 1 %filename - %size from %filesize downloaded (100%), at $round($calc( %size / (($ctime - %time) * 1000) ),2) kb/s.
    sockwrite -nt $sockname $base(%size, 10, 16)
  }

  goto nextread

}+  (
