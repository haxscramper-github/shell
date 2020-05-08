import strutils
import ssh_errors
import sequtils
import os
import bitops
import strformat
import net
import posix
import streams
import osproc
import strtabs

import libssh2

const defBufSize = 1024

type
  SSHError* = ref object of CatchableError
    rc*: int

  SSHConnection* = ref object
    session*: Session
    socket*: Socket
    channel*: Channel

    outbuf: string
    errbuf: string

  RemoteProcess = object
    connection*: SSHConnection
    exitStatus*: cint
    inStream*, outStream*, errStream*: Stream

  RemoteStream* = ref object of Stream
    conn*: SSHConnection ## Reference to SSH connection

  ShellProcKind* = enum
    spkRemote ## Remotely executed process
    spkLocal ## Locally executed process

  ShellProcess* = object
    case kind*: ShellProcKind
    of spkRemote:
      rproc*: RemoteProcess
    of spkLocal:
      lproc*: Process

  ShellCommand* = object
    cmdString*: string ## Shell command to start process
    workdir*: string ## Working directory of a process.
    args*: seq[string] ## Process arguments
    env*: StringTableRef ## Env values for a new proces

proc waitsocket(socket_fd: SocketHandle, s: Session): int =
  var timeout: Timeval
  var fd: TFdSet
  var writefd: TFdSet
  var readfd: TFdSet
  var dir: int

  timeout.tv_sec = 10.Time
  timeout.tv_usec = 0

  FD_ZERO(fd)
  FD_SET(socket_fd, fd)

  dir = s.sessionBlockDirections()

  if((dir and LIBSSH2_SESSION_BLOCK_INBOUND) == LIBSSH2_SESSION_BLOCK_INBOUND):
    readfd = fd

  if((dir and LIBSSH2_SESSION_BLOCK_OUTBOUND) == LIBSSH2_SESSION_BLOCK_OUTBOUND):
    writefd = fd

  var sfd  = cast[cint](socket_fd) + 1

  result = select(sfd, addr readfd, addr writefd, nil, addr timeout);




proc close*(c: SSHConnection) =
  discard c.session.sessionDisconnect("Normal shutdown, thank you for playing")
  discard c.session.sessionFree()
  c.socket.close()

proc sshInit*(hostname: string, port: int = 22): SSHConnection =
  ## Init ssh library, create new socket, init new ssh session
  var initDone {.global.} = false
  if not initDone:
    var rc = init(0)
    if rc != 0:
      raise SSHError(
        msg: "libssh2 initialization failed",
        rc: rc
      )

    initDone = true

  result = SSHConnection(
    socket: newSocket(),
    session: sessionInit()
  )

  result.socket.connect(hostname, Port(port))
  result.session.sessionSetBlocking(0)


proc sshHandshake*(c: var SSHConnection): void =
  var rc = 0
  while true:
    rc = c.session.sessionHandshake(c.socket.getFd())
    if rc != LIBSSH2_ERROR_EAGAIN:
      break

  if rc != 0:
    raise SSHError(
      msg: "failure establing ssh connection",
      rc: rc
    )

proc sshKnownHosts*(ssc: var SSHConnection, hostname: string): void =
  var knownHosts = ssc.session.knownHostInit()
  if knownHosts.isNil:
    ssc.close()

  # TODO replace with actual known hosts
  var rc = knownHosts.knownHostReadfile("dummy_known_hosts.tmp", LIBSSH2_KNOWNHOST_FILE_OPENSSH)

  if rc < 0:
    raise SSHError(
      msg: "Read knownhost error: " & $rc,
      rc: rc
    )

  var length: int
  var typ: int

  var fingerprint = ssc.session.sessionHostkey(length, typ)
  if fingerprint.isNil:
    ssc.close()
    raise SSHError(msg: "Unable to fetch hostkey")

  var host: knownhost_st
  let check = knownHosts.knownHostCheckP(
    hostname,
    22,
    fingerprint,
    length,
    LIBSSH2_KNOWNHOST_TYPE_PLAIN or LIBSSH2_KNOWNHOST_KEYENC_RAW or LIBSSH2_KNOWNHOST_KEY_SSHRSA,
    addr host
  )

  # echo "Host check: ",
  #     check, " key: ",
  #     if check <= LIBSSH2_KNOWNHOST_CHECK_MISMATCH: host.key else: "<none>"

  rc = knownHosts.knownHostAddC(
    hostname,
    nil,
    fingerprint,
    length,
    nil,
    0,
    LIBSSH2_KNOWNHOST_TYPE_PLAIN or LIBSSH2_KNOWNHOST_KEYENC_RAW or LIBSSH2_KNOWNHOST_KEY_SSHRSA,
    nil)

  if rc != 0:
    raise SSHError(
      msg: "Failed to add knownhost: " & $rc,
      rc: rc
    )

  knownHosts.knownHostWritefile("dummy_known_hosts.tmp", LIBSSH2_KNOWNHOST_FILE_OPENSSH)
  knownHosts.knownHostFree()

# TODO separate into two functions: public key OR password. Do not
# implicitly mix two different authentification methods.
proc sshAuth*(
  ssc: var SSHConnection,
  password: string = "",
  username: string,
  pubkeyFile: string = "~/.ssh/id_rsa.pub",
  privkeyFile: string = "~/.ssh/id_rsa",
     ): void =
  var rc = 0
  if password.len > 0:
    while true:
      rc = ssc.session.userauthPassword(username, password, nil)
      if rc != LIBSSH2_ERROR_EAGAIN:
        break

    if rc != 0:
      ssc.close()

      raise SSHError(
        msg: "Authentication by password failed!",
        rc: rc
      )

  else:
    while true:
      rc = ssc.session.userauthPublickeyFromFile(username, pubkeyFile, privkeyFile, password)
      if rc != LIBSSH2_ERROR_EAGAIN:
        break

    if rc != 0:
      ssc.close()
      raise SSHError(
        msg: "Authentication by public key failed!",
        rc: rc
      )

proc sshOpenChannel(ssc: var SSHConnection): void =
  var rc = 0
  # var channel: Channel
  while true:
    ssc.channel = ssc.session.channelOpenSession()
    if ssc.channel.isNil and ssc.session.sessionLastError(nil, nil, 0) == LIBSSH2_ERROR_EAGAIN:
      discard waitsocket(ssc.socket.getFd(), ssc.session)
    else:
      break

  if ssc.channel.isNil:
    echo "Unable to open a session"
    ssc.close()

proc sshExecCommand(ssc: var SSHConnection, command: string): void =
  var rc = 0
  while true:
    rc = ssc.channel.channelExec(command)
    if rc != LIBSSH2_ERROR_EAGAIN:
      break

  if rc != 0:
    # TODO Report error command and other necessary things to process
    # them on higher levels.
    ssc.close()
    raise SSHError(
      msg: "SSH Failed to execute command",
      rc: rc
    )


# iterator sshResultStdout(ssc: var SSHConnection): string {.closure.} =

iterator sshResultStderr(ssc: var SSHConnection): string {.closure.} =
  var rc = 0
  while true:
    var buffer: array[0..1024, char]
    rc = ssc.channel.channelReadStderr(addr buffer, buffer.len)
    if rc > 0:
      yield buffer[0 ..< rc].join()
    if rc == LIBSSH2_ERROR_EAGAIN:
      discard waitsocket(ssc.socket.getFd(), ssc.session)
    else:
      break




proc sshCommandGetExit(
  ssc: SSHConnection): tuple[code: int, signal: cstring] =
  var rc = 0
  var  exitcode = 127
  while true:
    rc = ssc.channel.channelClose()
    if rc == LIBSSH2_ERROR_EAGAIN:
      discard waitsocket(ssc.socket.getFd(), ssc.session)
    else:
      break

  var exitsignal: cstring

  if rc == 0:
    exitcode = ssc.channel.channelGetExitStatus()
    discard ssc.channel.channelGetExitSignal(exitSignal, 0, nil, 0, nil, 0)


  discard ssc.channel.channelFree()


proc startProcess*(ssc: var SSHConnection, command: string): RemoteProcess =
  ssc.sshExecCommand(command)

  return RemoteProcess(
    connection: ssc
  )


proc startProcess*(cmd: ShellCommand): ShellProcess =
  ShellProcess(
    kind: spkLocal,
    lproc: startProcess(
      command = cmd.cmdString,
      workingDir = cmd.workdir,
      args = cmd.args,
      env = cmd.env
    )
  )


proc startProcess*(conn: var SSHConnection, cmd: ShellCommand): ShellProcess =
  ShellProcess(
    kind: spkRemote,
    rproc: conn.startProcess(cmd.cmdString)
  )

proc startShellProcess*(conn: var SSHConnection, cmd: string): ShellProcess =
  conn.startProcess(
    cmd = ShellCommand(cmdString: cmd)
  )

proc openSSHConnection*(
  hostname,
  username: string,
  password: string = "",
  pubkeyFile: string = "~/.ssh/id_rsa.pub",
  privkeyFile: string = "~/.ssh/id_rsa",
     ): SSHConnection =
  var ssc = sshInit(hostname = hostname)
  ssc.sshHandshake()

  ssc.sshKnownHosts(hostname = hostname)
  ssc.sshAuth(
    username = username,
    password = password,
    pubkeyFile = pubkeyFile,
    privkeyFile = privkeyFile
  )

  ssc.sshOpenChannel()

  return ssc


proc noMoreData(
  conn: var SSHConnection,
  isErr: static[bool] = false): bool =
  ## Return true if no more data can be read from a connection
  ## channel. This might be due to several reasons: ssh error or
  ## process has terminated. Testing is done separately on `stderr`
  ## and `stdout` for a channel.
  when isErr:
    if conn.errbuf.len > 0: return false
  else:
    if conn.outbuf.len > 0: return false

  while true:
    var buf: array[1024, char]
    let rc =
      when isErr:
        conn.channel.channelReadStderr(addr buf, sizeof buf)
      else:
        conn.channel.channelRead(addr buf, sizeof buf)

    if rc == 0:
      # echo "\tssh no more data to read from ", (if isErr: "err" else: "out")
      return true
    elif rc == LIBSSH2_ERROR_EAGAIN:
      # echo "\tssh reading again, rc: " & $rc
      discard waitsocket(conn.socket.getFd(), conn.session)
    elif rc > 0:
      # echo "\tssh has data to read, appending test buffer, rc: ",
      #    rc, " recieved size: "

      when isErr:
        conn.errbuf &= buf[0 ..< rc].join()
      else:
        conn.outbuf &= buf[0 ..< rc].join()

      return false
    else:
      # echo "\tssh read returned error " & $rc
      return true

proc running*(rproc: var RemoteProcess): bool =
  not (
    rproc.connection.noMoreData(isErr = false) and
    rproc.connection.noMoreData(isErr = true)
  )

proc close*(sproc: ShellProcess, connectionClose: bool = false): void =
  case sproc.kind:
    of spkLocal:
      sproc.lproc.close()
    else:
      if connectionClose:
        sproc.rproc.connection.close()


proc running*(sproc: var ShellProcess): bool =
  case sproc.kind:
    of spkLocal:
      sproc.lproc.running()
    of spkRemote:
      sproc.rproc.running()

proc canReadStdout*(sproc: var ShellProcess): bool =
  case sproc.kind:
    of spkLocal:
      sproc.lproc.running()
    of spkRemote:
      not sproc.rproc.connection.noMoreData(isErr = false)

proc canReadStderr*(sproc: var ShellProcess): bool =
  case sproc.kind:
    of spkLocal:
      sproc.lproc.running()
    of spkRemote:
      not sproc.rproc.connection.noMoreData(isErr = true)

proc peekExitCode*(sproc: ShellProcess): int =
  case sproc.kind:
    of spkLocal:
      sproc.lproc.peekExitCode()
    of spkRemote:
      sproc.rproc.connection.sshCommandGetExit().code

template bufferedReadLine(atEnd, buffer, lineResult: typed): untyped =
  ## Read single line into variable `lineResult` from buffer `buffer`
  ## using `atEnd` to check for input end. It is assumed that `atEnd`
  ## performs test reading into buffer and thus `while not atEnd` will
  ## run until there is no more data. When line is read `return true`
  ## is executed.
  while not atEnd:
    let eol = buffer.find({'\0', '\L', '\c', '\n'})
    if eol != -1:
      lineResult = buffer[0 ..< eol]
      buffer = buffer[eol + 1 .. ^1]
      return true

  lineResult = buffer
  buffer = ""

proc processOutput(rproc: var RemoteProcess, isErr: static[bool] = false): RemoteStream =
  new(result)
  result.conn = rproc.connection

  result.atEndImpl =
    proc(s: Stream): bool =
      var conn = (cast[RemoteStream](s)).conn
      conn.noMoreData()

  result.readDataImpl =
    proc(s: Stream, buffer: pointer, buflen: int): int =
      var conn = (cast[RemoteStream](s)).conn

      when isErr:
        if conn.errbuf.len > 0:
          echo "\tcan read stderr from buffer"
      else:
        # echo "\treading from stdout"
        if conn.outbuf.len == 0 and conn.noMoreData():
          echo "buffer is empty and no data can be read"
          return 0

        let toRead = min(conn.outbuf.len, buflen)
        copymem(buffer, conn.outbuf.cstring, toRead)
        conn.outbuf = conn.outbuf[toRead..^1]
        return toRead

  result.readLineImpl =
    proc(s: Stream, line: var TaintedString): bool =
      var conn = (cast[RemoteStream](s)).conn
      when isErr:
        discard

      else:
        bufferedReadLine(
          atEnd = conn.noMoredata(),
          buffer = conn.outbuf,
          lineResult = line
        )
        # while not conn.noMoreData():
        #   let eol = conn.outbuf.find({'\0', '\L', '\c', '\n'})
        #   # echo conn.outbuf.mapIt(it)
        #   # echo "eol is: ", eol
        #   if eol != -1:
        #     line = conn.outbuf[0 ..< eol]
        #     conn.outbuf = conn.outbuf[eol + 1 .. ^1]
        #     return true

        # line = conn.outbuf
        # conn.outbuf = ""


proc outputStream*(rproc: var RemoteProcess): Stream =
  rproc.processOutput(false)

proc errorStream*(rproc: var RemoteProcess): Stream =
  rproc.processOutput(true)

proc outputStream*(sproc: var ShellProcess): Stream =
  case sproc.kind:
    of spkLocal:
      sproc.lproc.outputStream()
    of spkRemote:
      sproc.rproc.outputStream()

proc errorStream*(sproc: var ShellProcess): Stream =
  case sproc.kind:
    of spkLocal:
      sproc.lproc.errorStream()
    of spkRemote:
      sproc.rproc.errorStream()



proc main() =
  var ssc = openSSHConnection(
    username = "ssh-test-user",
    password = "ssh-password",
    hostname = "127.0.0.1"
  )

  var rproc = ssc.startShellProcess("ls /")
  while rproc.canReadStdout():
    echo "-> ", rproc.outputStream().readLine()

# main()

proc getSessionError*(s: Session): tuple[rc: cint, msg: string] =
  var errbuf = allocCStringArray([""])
  var errlen: cint = 0
  let err = s.sessionLastError(addr errbuf[0], addr errlen, 0)
  let msg = $errbuf[0]
  deallocCStringArray(errbuf)

  return (rc: err, msg: msg)


type
  SFTPFStream = ref object of Stream
    mode: FileMode
    channel: Channel ## SSH Channel for remote file
    handle: SftpHandle
    session: Sftp
    buffer: string

proc bitand[T: SomeInteger](ints: openarray[T]): T =
  toSeq(ints).foldl(bitand(a, b))

func fileModeToLibSSH(mode: FileMode): int =
  case mode:
    of fmWrite: bitand [
      LIBSSH2_FXF_WRITE,
      LIBSSH2_FXF_CREAT,
      LIBSSH2_FXF_TRUNC
    ]

    of fmRead: bitand [
      LIBSSH2_FXF_READ
    ]

    of fmReadWrite: bitand [
      LIBSSH2_FXF_WRITE,
      LIBSSH2_FXF_READ,
      LIBSSH2_FXF_CREAT,
      LIBSSH2_FXF_TRUNC
    ]

    of fmReadWriteExisting: bitand [
      LIBSSH2_FXF_WRITE,
      LIBSSH2_FXF_READ,
      LIBSSH2_FXF_TRUNC
    ]

    of fmAppend: bitand [
      LIBSSH2_FXF_WRITE,
      LIBSSH2_FXF_CREAT,
      LIBSSH2_FXF_APPEND
    ]


proc noMoreData(sftp: SFTPFStream): bool =
  ## Return `true` if no more data can be read from remote file. If
  ## `sftp` buffer is empty test read is done to check for data
  ## availability: stream buffer is updated (result of the test read
  ## is appended to the buffer).

  if sftp.buffer.len > 0:
    return false

  while true:
    var buf: array[1024, char]
    let rc = sftp.handle.sftpRead(addr buf, sizeof buf)

    echo "\tread ", rc, " bytes from handle"

    if rc == 0:
      return true
    elif rc == LIBSSH2_ERROR_EAGAIN:
      echo "\ttrying to read again"
      discard
    elif rc < 0:
      echo "\tno more data"
      return true
      # raise SSHError(
      #   msg: "Failed to read from remote",
      #   rc: rc
      # )

    else:
      sftp.buffer &= buf[0 .. rc].join()
      return false


proc initSFTPStream(s: var SFTPFStream): void =
  s.closeImpl =
    proc(s: Stream): void =
      var sftp = cast[SFTPFStream](s)
      discard sftp.handle.sftpClose()
      discard sftp.session.sftpShutdown()

  s.atEndImpl =
    proc(s: Stream): bool =
      var sftp = cast[SFTPFStream](s)
      return sftp.noMoreData()

  s.readDataImpl =
    proc(s: Stream, buffer: pointer, buflen: int): int =
      var sftp = SFTPFStream(s)
      # NOTE cannot raise in streams implementation
      # assert sftp.mode in {fmRead, fmReadWriteExisting, fmReadWrite},
      #   &"Cannot read from SFTP file stream confgured as {sftp.mode}"

      var readCount = 0
      while readCount < buflen:
        echo "\treading more data from buffer"
        if sftp.noMoreData():
          echo "\tin total read ", readCount, " from remote file"
          return readCount
        else:
          let tocopy = min(sftp.buffer.len , buflen - readCount)

          copymem(buffer, sftp.buffer.cstring, tocopy)
          sftp.buffer = sftp.buffer[tocopy .. ^1]

          readCount += tocopy

      echo "\treads", readCount, "bytes from input stream, can read more"
      return readCount

      # if sftp.buffer.len == 0: # has data in buffer, reading it first
      #   copymem(buffer, sftp.buffer.cstring, copylen)
      #   sftp.buffer = sftp.buffer[buflen .. ^1]
      # else: # No data in buffer, need to read from remote first

      #   # Read data into buffer
      #   sftp.buffer = newStringOfCap(defBufSize)
      #   discard sftp.handle.sftpRead(sftp.buffer.cstring, defBufSize)

      #   # Cann proc again - this is not realy a recurisve call since
      #   # only one level should be ever active.
      #   return s.readDataImpl(s, buffer, buflen)

proc sftpFStat(s: Sftp, remotepath: string): SftpAttributes =
  var handle = s.sftpOpen(
    filename = remotepath.cstring,
    flags = cast[int32](fileModeToLibSSH(fmRead)),
    mode = 0007
  )

  while true:
    echo "sftp stat"
    let rc = sftp_fstat_ex(handle, result, 0)
    if rc == LIBSSH2_ERROR_EAGAIN:
      echo rc, ": ", getErrorName(rc)
      discard
    elif rc < 0:
      raise SSHError(
        msg: "Failed to read stat from file, rc: " & $rc & ", " & getErrorName(rc),
        rc: rc
      )

    else:
      discard handle.sftp_close()
      return result


proc openSftpStream(
  s: Sftp,
  remotepath: string,
  remotemode: FileMode = fmWrite,
  permissions: int = 0777
     ): SFTPFStream =
  ## Open file in new sftp session. Closing file will close the
  ## session
  new(result)
  initSFTPStream(result)

  result.mode = remotemode
  result.session = s

  let attrs = sftpFStat(s, remotepath)

  let flags = fileModeToLibSSH(remotemode)
  result.handle = result.session.sftpOpen(
    filename = remotepath.cstring,
    flags = cast[int32](flags),
    mode = cast[int32](bitand(permissions, 0777))
  )


#=======================  exposed SFTP functions  ========================#

proc sftpInit*(s: SSHConnection): Sftp =
  ## Open SFT session within ssh session `s`
  result = s.session.sftpInit()
  if result.isNil():
    let rc = cast[int](result.sftp_last_error())

    raise SSHError(
      rc: rc,
      msg:
        if rc > 0: getSftpErrorName(rc)
        else: getErrorName(rc)
    )

proc copyFileTo*(s: Sftp, source, dest: string): void =
  ## Copy local file `source` to remote file `dest`
  var stream = s.openSftpStream(
    remotepath = dest,
    remotemode = fmWrite
  )


  stream.close()

proc copyFileFrom*(s: Sftp, source, dest: string): void =
  ## Copy remote file `source` to local path `dest`
  discard

proc readFile*(s: Sftp, file: string): string =
  ## Read content of the remote file
  discard

proc openFileRead*(s: Sftp, file: string): SFTPFStream =
  ## Open remote file sftp stream
  result = s.openSftpStream(
    remotepath = file,
    remotemode = fmRead
  )

proc readLine*(s: var SFTPFStream): string =
  discard s.readLine(result)

#=========================  SCP file operations  =========================#

proc scpSendFile*(
  ssc: var SSHConnection,
  localPath, remotePath: string,
  permissions: int = 0777): void =

  let fileStat =
    block:
      var res: Stat
      let rc = stat(localPath.cstring, res)
      # IMPLEMENT check error code
      res

  assert localPath.fileExists()

  var channel: Channel
  while channel == nil: # REFACTOR into separate function
    channel = ssc.session.scpSend(
      path = remotePath,
      mode = bitand(
        cast[int](fileStat.stMode),
        permissions),
      size = fileStat.stSize
    )

    if channel == nil:
      let (err, msg) = ssc.session.getSessionError()
      if err != LIBSSH2_ERROR_EAGAIN:
        raise SSHError(
          msg: &"Unable to open session. {msg} rc: {err}",
          rc: err
        )

  echo "\t created channel"
  var file = localPath.open()

  var buf: array[1024, char]
  while true:
    var nread = file.readBuffer(addr buf, 1024)
    var bufpos = 0

    if nread == 0:
        break

    echo &"\tread {nread} from file"

    while bufpos < nread: # Until we send buffer
      let rc = channel.channelWrite(addr buf, nread)

      if rc < 0 and rc != LIBSSH2_ERROR_EAGAIN:
        let (err, msg) = ssc.session.getSessionError()
        raise SSHError(
          msg: msg,
          rc: err
        )

      elif rc == LIBSSH2_ERROR_EAGAIN:
        discard

      else:
        bufpos += rc
        echo &"\tsent {rc} bytes"

  file.close()
  discard channel.channelSendEOF()
  discard channel.channelWaitEOF()
  discard channel.channelWaitClosed()
  discard channel.channelFree()
  channel = nil
