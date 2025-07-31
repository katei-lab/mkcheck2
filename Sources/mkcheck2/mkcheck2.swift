import ArgumentParser
import Foundation
import Logging
import SystemPackage
import mkcheck2abi
import mkcheck2bpf_skelton
import mkcheck2syslinux

let logger = Logger(label: "mkcheck2")

@main
struct Mkcheck2: ParsableCommand {

  enum OutputFormat: String, ExpressibleByArgument {
    case json
    case dot
    case ascii
    case none
  }
  struct LogLevel: ExpressibleByArgument {
    let underlying: Logger.Level
    init(_ level: Logger.Level) {
      self.underlying = level
    }

    init?(argument: String) {
      guard let level = Logger.Level(rawValue: argument) else { return nil }
      self.underlying = level
    }
  }

  struct TraceOptions: ParsableArguments {
    @Option(name: .shortAndLong, help: "The output file to write the trace")
    var output: String?

    @Option(name: .shortAndLong, help: "The output format")
    var format: OutputFormat = .json

    @Option(name: .long, help: "The log level")
    var logLevel: LogLevel = LogLevel(.warning)

    func bootstrapLogger() {
      LoggingSystem.bootstrap { label in
        var handler = StreamLogHandler.standardOutput(label: label)
        handler.logLevel = self.logLevel.underlying
        return handler
      }
    }
  }

  struct Pid: ParsableCommand {
    @OptionGroup()
    var traceOptions: TraceOptions
    @Argument(help: "The process ID to trace")
    var pid: Int

    func run() throws {
      try Mkcheck2.trace(pid: pid_t(pid)).run(options: traceOptions)
    }
  }

  struct Command: ParsableCommand {
    @OptionGroup()
    var traceOptions: TraceOptions

    @Argument(parsing: .postTerminator)
    var args: [String]

    func run() throws {
      traceOptions.bootstrapLogger()

      logger.info("Command: \(args.joined(separator: " "))")
      guard !args.isEmpty else {
        throw Mkcheck2Error("No command specified")
      }

      switch fork() {
      case -1:
        throw Mkcheck2Error("Failed to fork")
      case 0:
        try Mkcheck2.dropPrivileges()
        raise(SIGSTOP)  // Wait for the parent to attach the BPF program
        var argv = args.map { strdup($0) }
        argv.append(nil)
        execvp(argv[0]!, argv)
        let error = String(cString: strerror(errno))
        for arg in argv.dropLast() {
          free(arg)
        }
        throw Mkcheck2Error("Failed to execvp \(args): \(error)")
      case let pid:
        var status: Int32 = 0
        // Wait for the child until the process is ready to exec
        logger.info("Waiting for PID \(pid)")
        let readyPID = waitpid(pid, &status, WUNTRACED)
        assert(pid == readyPID, "waitpid returned unexpected PID")
        logger.info("Child stopped with status \(status)")
        guard swift_WSTOPSIG(status) == SIGSTOP else {
          throw Mkcheck2Error("Child did not stop!?")
        }
        // Attach the BPF program to the child
        logger.info("Tracing PID \(pid)")
        do {
          let tracer = try Mkcheck2.trace(pid: pid)
          // Resume the child so it can exec
          logger.info("Resuming PID \(pid)")
          kill(pid, SIGCONT)
          try tracer.run(options: traceOptions)
        } catch {
          if !(error is ExitCode) {
            logger.warning("Error: \(error)")
          }
          kill(pid, SIGKILL)
          throw error
        }
      }
    }
  }

  struct Diff: ParsableCommand {
    @Argument(help: "The first trace file")
    var first: String

    @Argument(help: "The second trace file")
    var second: String

    func run() throws {
      let trace1 = try loadTrace(first)
      let trace2 = try loadTrace(second)

      var fileIDByPath1: [FilePath: FileID] = [:]
      var fileIDByPath2: [FilePath: FileID] = [:]
      var fileInfoByID1: [FileID: Serialization.FileInfo] = [:]
      var fileInfoByID2: [FileID: Serialization.FileInfo] = [:]
      for fileInfo in trace1.files {
        fileInfoByID1[fileInfo.id] = fileInfo
        fileIDByPath1[fileInfo.name] = fileInfo.id
      }
      for fileInfo in trace2.files {
        fileInfoByID2[fileInfo.id] = fileInfo
        fileIDByPath2[fileInfo.name] = fileInfo.id
      }

      let filePaths1 = Set(fileIDByPath1.keys)
      let filePaths2 = Set(fileIDByPath2.keys)

      let commonPaths = filePaths1.intersection(filePaths2)
      let uniquePaths1 = filePaths1.subtracting(filePaths2)
      let uniquePaths2 = filePaths2.subtracting(filePaths1)

      for path in commonPaths {
        let id1 = fileIDByPath1[path]!
        let id2 = fileIDByPath2[path]!
        let info1 = fileInfoByID1[id1]!
        let info2 = fileInfoByID2[id2]!
        if info1.deleted != info2.deleted {
          print("* \(path): deleted status mismatch: \(info1.deleted!) vs \(info2.deleted!)")
        }
        if info1.exists != info2.exists {
          print("* \(path): exists status mismatch: \(info1.exists!) vs \(info2.exists!)")
        }
        if info1.deps != info2.deps {
          print("* \(path): dependency mismatch: \(info1.deps!) vs \(info2.deps!)")
        }
      }

      for path in uniquePaths1 {
        let id = fileIDByPath1[path]!
        let info = fileInfoByID1[id]!
        guard !shouldSkip(info) else { continue }
        print("+ \(path): \(info.onelineAttributes)")
      }

      for path in uniquePaths2 {
        let id = fileIDByPath2[path]!
        let info = fileInfoByID2[id]!
        guard !shouldSkip(info) else { continue }
        print("- \(path): \(info.onelineAttributes)")
      }
    }

    private func shouldSkip(_ info: Serialization.FileInfo) -> Bool {
      let path = info.name
      return path.starts(with: "/tmp/") || path.starts(with: "/proc/") || path.starts(with: "/dev/")
        || info.deleted == true
    }

    private func loadTrace(_ path: String) throws -> DumpFormat {
      let data = try Data(contentsOf: URL(fileURLWithPath: path))
      let decoder = JSONDecoder()
      var format = try decoder.decode(DumpFormat.self, from: data)
      format.normalize()
      return format
    }
  }

  static let configuration = CommandConfiguration(
    commandName: "mkcheck2",
    subcommands: [Command.self, Pid.self, Diff.self],
    defaultSubcommand: Command.self
  )

  static func trace(pid: pid_t) throws -> Tracer {
    guard let obj = mkcheck2_bpf__open() else {
      throw Mkcheck2Error("Failed to open BPF object")
    }
    logger.info("Tracing PID \(pid)")
    obj.pointee.rodata.pointee.root_ppid = pid
    guard mkcheck2_bpf__load(obj) == 0 else {
      throw Mkcheck2Error("Failed to load BPF object: \(String(cString: strerror(errno)))")
    }

    guard mkcheck2_bpf__attach(obj) == 0 else {
      throw Mkcheck2Error("Failed to attach BPF object: \(String(cString: strerror(errno)))")
    }

    return try Tracer(root: pid, obj: obj)
  }

  static func dropPrivileges() throws {
    guard getuid() == 0 else { return }
    guard let sudoGID = ProcessInfo.processInfo.environment["SUDO_GID"],
      let sudoUID = ProcessInfo.processInfo.environment["SUDO_UID"]
    else {
      // For the case where the root user directly runs the command without sudo, just
      // run the subsequent process as root.
      return
    }
    let gid = gid_t(Int(sudoGID)!)
    let uid = uid_t(Int(sudoUID)!)
    guard setgid(gid) == 0 else {
      throw Mkcheck2Error("Failed to set GID: \(String(cString: strerror(errno)))")
    }
    guard setuid(uid) == 0 else {
      throw Mkcheck2Error("Failed to set UID: \(String(cString: strerror(errno)))")
    }
  }
}

struct Mkcheck2Error: Error, CustomStringConvertible {
  let description: String

  init(_ description: String) {
    self.description = description
  }
}

extension UnsafeMutablePointer where Pointee == mkcheck2_event {
  var pathString: String? {
    get throws {
      return try UnsafeRawPointer(self).advanced(
        by: MemoryLayout<mkcheck2_event>.offset(of: \.path)!
      ).withMemoryRebound(to: mkcheck2_path_t.self, capacity: 1) { base -> String? in
        return try base.readPathString()
      }
    }
  }
  var path: FilePath? {
    get throws {
      guard let pathString = try pathString else { return nil }
      return FilePath(pathString)
    }
  }

  var pathOrInode: FilePath {
    get throws {
      if let path = try path {
        return path
      } else {
        return FilePath("/inode:\(self.pointee.payload)")
      }
    }
  }
}

extension UnsafeMutablePointer where Pointee == mkcheck2_fat_event {
  var pathStrings: (String?, String?) {
    get throws {
      let path0 = try UnsafeRawPointer(self).advanced(
        by: MemoryLayout<mkcheck2_fat_event>.offset(of: \.path.0)!
      ).withMemoryRebound(to: mkcheck2_path_t.self, capacity: 1) { base -> String? in
        return try base.readPathString()
      }
      let path1 = try UnsafeRawPointer(self).advanced(
        by: MemoryLayout<mkcheck2_fat_event>.offset(of: \.path.1)!
      ).withMemoryRebound(to: mkcheck2_path_t.self, capacity: 1) { base -> String? in
        return try base.readPathString()
      }
      return (path0, path1)
    }
  }

  var paths: (FilePath?, FilePath?) {
    get throws {
      let (path0, path1) = try pathStrings
      return (path0.map { FilePath($0) }, path1.map { FilePath($0) })
    }
  }
}

extension UnsafeMutablePointer where Pointee == mkcheck2_fat2_event {
  var pathStrings: (String?, String?, String?, String?) {
    get throws {
      func readPathString(at keyPath: KeyPath<mkcheck2_fat2_event, mkcheck2_path_t>) throws
        -> String?
      {
        let offset = MemoryLayout<mkcheck2_fat2_event>.offset(of: keyPath)!
        return try UnsafeRawPointer(self).advanced(by: offset).withMemoryRebound(
          to: mkcheck2_path_t.self, capacity: 1
        ) { base -> String? in
          return try base.readPathString()
        }
      }
      return try (
        readPathString(at: \.path.0), readPathString(at: \.path.1),
        readPathString(at: \.path.2), readPathString(at: \.path.3)
      )
    }
  }

  var paths: (FilePath?, FilePath?, FilePath?, FilePath?) {
    get throws {
      let (path0, path1, path2, path3) = try pathStrings
      return (
        path0.map { FilePath($0) }, path1.map { FilePath($0) }, path2.map { FilePath($0) },
        path3.map { FilePath($0) }
      )
    }
  }
}

extension UnsafePointer where Pointee == mkcheck2_path_t {
  func readPathString() throws -> String? {
    guard self.pointee.0.0 != 0 else {
      return nil
    }
    return try self.withMemoryRebound(
      to: CChar.self, capacity: Int(DEFAULT_SUB_BUF_LEN * DEFAULT_SUB_BUF_SIZE)
    ) { base -> String? in
      var buffer: [String] = []
      for chunkIndex in 0..<Int(DEFAULT_SUB_BUF_LEN) {
        let chunkBase = base.advanced(by: chunkIndex * Int(DEFAULT_SUB_BUF_SIZE))
        guard chunkBase.pointee != 0 else { break }
        guard let chunk = String(utf8String: chunkBase) else {
          throw Mkcheck2Error("mkcheck2_path_t contains ill-formed UTF-8 string")
        }
        buffer.append(chunk)
      }
      // drop the first chunk which is the "/" root
      return buffer.last! + buffer.dropLast().reversed().joined(separator: "/")
    }
  }
}

@_cdecl("stophere") func stophere() {
  raise(SIGSTOP)
}

extension mkcheck2_event_header {
  var type: mkcheck2_event_type {
    return mkcheck2_event_type(rawValue: self._type)!
  }
}

extension mkcheck2_event_type: @retroactive CustomStringConvertible {
  public var description: String {
    switch self {
    case .eventTypeExec: return "EXEC"
    case .eventTypeExit: return "EXIT"
    case .eventTypeInput: return "INPUT"
    case .eventTypeOutput: return "OUTPUT"
    case .eventTypeRemove: return "REMOVE"
    case .eventTypeRename: return "RENAME"
    case .eventTypeChdir: return "CHDIR"
    case .eventTypeClone: return "CLONE"
    case .eventTypeInputAt: return "INPUTAT"
    case .eventTypeOutputAt: return "OUTPUTAT"
    case .eventTypeLink: return "LINK"
    case .eventTypeSymlink: return "SYMLINK"
    case .eventTypeRemoveAt: return "REMOVEAT"
    case .eventTypeLinkAt: return "LINKAT"
    case .eventTypeRenameAt: return "RENAMEAT"
    case .eventTypeSymlinkAt: return "SYMLINKAT"
    case .eventTypeExecAt: return "EXECAT"
    }
  }
}

extension mkcheck2_error_type: @retroactive CustomStringConvertible {
  public var description: String {
    switch self {
    case .errorRingBufferFull: return "Ring buffer is full"
    case .errorStagingEventFull: return "Staging event is full"
    case .errorStagingEventNotAllocated: return "Staging event is not allocated"
    case .errorReadUserStr: return "Failed to read user string"
    case .errorReadDentryStr: return "Failed to read dentry strings"
    case .errorStagingConflict: return "Failed to stage event due to conflict"
    }
  }
}

extension mkcheck2_error: @retroactive CustomStringConvertible {
  public var description: String {
    let type = mkcheck2_error_type(rawValue: type)?.description ?? "Unknown error"
    return "\(type) (line: \(self.line))"
  }
}
