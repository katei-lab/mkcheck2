import ArgumentParser
import Foundation
import SystemPackage
import mkcheck2abi
import mkcheck2bpf_skelton
import mkcheck2syslinux

class Tracer {
  let rb: OpaquePointer
  /// struct bpf_map* for fatal errors
  let fatalErrors: OpaquePointer
  let obj: UnsafeMutablePointer<mkcheck2_bpf>
  let trace: Trace

  init(root: pid_t, obj: UnsafeMutablePointer<mkcheck2_bpf>) throws {
    self.obj = obj
    let trace = Trace(root: root)
    let context = Unmanaged.passRetained(trace)
    self.trace = trace

    guard
      let rb = ring_buffer__new(
        bpf_map__fd(obj.pointee.maps.events),
        { (ctx, data, size) in
          let event = data!.bindMemory(to: mkcheck2_event_header.self, capacity: 1)
          let context = Unmanaged<Trace>.fromOpaque(ctx!)
          do {
            try context.takeUnretainedValue().handleEvent(event)
          } catch {
            logger.error("Error: \(error)")
            exit(1)
          }
          return 0
        },
        context.toOpaque(), nil
      )
    else {
      throw Mkcheck2Error("Failed to create ring buffer")
    }
    self.fatalErrors = obj.pointee.maps.fatal_errors
    self.rb = rb
  }

  private func checkFatalErrors() throws {
    var fatalErrorKey: UInt32 = 0
    var fatalErrorInfo = mkcheck2_error()
    let fatalErrorFd = bpf_map__fd(fatalErrors)
    let ret = bpf_map_lookup_elem(fatalErrorFd, &fatalErrorKey, &fatalErrorInfo)
    if ret == 0 {
      logger.error("Fatal error from BPF program: \(fatalErrorInfo.description)")
      throw ExitCode(1)
    }
  }

  func run(options: Mkcheck2.TraceOptions) throws {
    logger.info("STATE PID FNAME")
    logger.info("Tracing...")
    while trace.rootExitCode == nil {
      logger.info("Polling...")
      guard ring_buffer__poll(rb, 100 /* ms */) >= 0 else {
        if errno == EINTR {
          continue
        }
        let message = "Failed to poll ring buffer: \(String(cString: strerror(errno)))"
        throw Mkcheck2Error(message)
      }
      try checkFatalErrors()
    }
    try checkFatalErrors()
    let consumed = ring_buffer__consume(rb)
    logger.info("Done consuming \(consumed) events")
    let rootExitCode = trace.rootExitCode!
    guard rootExitCode == 0 else { throw ExitCode(rootExitCode) }

    if let outputPath = options.output {
      var output = ""
      switch options.format {
      case .json:
        trace.dump(output: &output)
      case .dot:
        trace.dumpDot(output: &output)
      case .ascii:
        trace.dumpAscii(output: &output)
      case .none: return
      }
      try output.write(toFile: outputPath, atomically: false, encoding: .utf8)
      print("Trace written to \(outputPath)")
    }
  }

  deinit {
    ring_buffer__free(rb)
    // FIXME: Destroying BPF links is slow (takes 1-2 seconds)
    mkcheck2_bpf__destroy(obj)
  }
}

typealias UID = UInt64
typealias FileID = UInt64

class Trace {
  let root: pid_t
  let selfPid: pid_t
  private(set) var rootExitCode: Int32?

  /// The next file ID to assign
  private var nextFileID: FileID = 1

  class Process: Codable {
    /// The process ID
    let pid: pid_t
    /// The parent process UID
    let parent: UID
    /// The unique entity ID
    let uid: UID
    /// The image file ID
    var image: FileID
    /// The input file IDs
    var inputs: Set<FileID> = []
    /// The output file IDs
    var outputs: Set<FileID> = []
    /// XXX: ???
    var pipeCount: Int = 0
    /// The current working directory
    var cwd: FilePath

    init(pid: pid_t, parent: UID, uid: UID, image: FileID, cwd: FilePath) {
      self.pid = pid
      self.parent = parent
      self.uid = uid
      self.image = image
      self.cwd = cwd
    }

    func addInput(_ path: FilePath, trace: Trace) {
      inputs.insert(trace.find(path: normalize(path: path)))
    }

    func addOutput(_ path: FilePath, trace: Trace) {
      let path = normalize(path: path)
      outputs.insert(trace.find(path: path))
      // XXX: Is this correct?
      let parent = trace.find(path: path.removingLastComponent())
      if !outputs.contains(parent) {
        inputs.insert(parent)
      }
    }

    func link(target: FilePath, linkPath: FilePath, trace: Trace) {
      trace.addDependency(source: target, dest: linkPath)
      addOutput(linkPath, trace: trace)
    }

    func rename(source: FilePath, dest: FilePath, trace: Trace) {
      trace.unlink(path: source)
      trace.addDependency(source: source, dest: dest)
      addOutput(dest, trace: trace)
    }

    /// Set the current working directory
    func setCurrentWorkingDirectory(_ path: FilePath) {
      cwd = normalize(path: path)
    }

    func normalize(path: FilePath) -> FilePath {
      return normalize(base: self.cwd, path: path)
    }

    func normalize(base: FilePath, path: FilePath) -> FilePath {
      let fullPath = base.pushing(path).lexicallyNormalized()
      guard
        let resolved = try? FileManager.default.destinationOfSymbolicLink(atPath: fullPath.string)
      else {
        return fullPath
      }
      let fullParent = fullPath.removingLastComponent()
      return fullParent.pushing(FilePath(resolved)).lexicallyNormalized()
    }
  }

  private(set) var procs: [pid_t: Process] = [:]
  /// A map from file paths to file IDs
  private var fileIDs: [FilePath: FileID] = [:]

  struct FileInfo: Codable {
    /// The file path
    let name: FilePath
    /// Whether the file has been deleted
    var deleted: Bool
    /// Whether the file exists
    /// XXX: Really needed?
    var exists: Bool
    /// The file dependencies
    ///
    /// ## Discussion
    /// This field is used to track the dependencies between files
    /// precisely. Unless this information, the file dependencies are hoisted
    /// to the process level and the computed dependency graph can be redundant.
    ///
    /// e.g. if we have the following trace:
    ///   PID1: rename(A, B)
    ///   PID1: rename(C, D)
    ///   PID2: read(B)
    ///   PID2: write(E)
    ///
    /// If we hoist the file dependencies to the process level, we will get:
    ///   A -> B -> E
    ///   C -> D
    ///   A -> D
    ///   C -> B
    ///
    /// However, A -> D and C -> B are not real dependencies. Instead, the precise
    /// dependency graph should be:
    ///   A -> B -> E
    ///   C -> D
    ///
    /// Reducing the redundancy in the dependency graph can help to find more redundant
    /// dependency edges in Makefiles. So we need to track the file dependencies precisely
    /// as much as possible.
    var deps: [FileID]
  }
  private(set) var fileInfos: [FileID: FileInfo] = [:]

  init(root: pid_t, selfPid: pid_t = getpid()) {
    self.root = root
    self.selfPid = selfPid

    // Add the root process
    let rootProc = Process(
      pid: root, parent: 0, uid: 0, image: find(path: "/__root__"),
      cwd: FilePath(FileManager.default.currentDirectoryPath))
    procs[root] = rootProc

    let selfProc = Process(
      pid: selfPid, parent: 0, uid: 0, image: find(path: "/__self__"),
      cwd: FilePath(FileManager.default.currentDirectoryPath))
    procs[selfPid] = selfProc
  }

  /// Returns true if the given UID is the root or the parent of the root process
  func shouldTrace(pid: pid_t) -> Bool {
    return pid != self.selfPid
  }

  /// Finds a file and returns file ID
  func find(path: FilePath) -> FileID {
    if let id = fileIDs[path] {
      return id
    }
    let id = nextFileID
    nextFileID += 1
    fileIDs[path] = id
    // FIXME: Check if the file exists
    fileInfos[id] = FileInfo(name: path, deleted: false, exists: true, deps: [])
    return id
  }

  func unlink(path: FilePath) {
    let id = find(path: path)
    fileInfos[id]!.deleted = true
    fileInfos[id]!.exists = false
  }

  func addDependency(source: FilePath, dest: FilePath) {
    let sourceID = find(path: source)
    let destID = find(path: dest)
    fileInfos[sourceID]!.deps.append(destID)
  }

  func withProcess(
    _ event: UnsafeMutablePointer<mkcheck2_event_header>, _ body: (inout Process) throws -> Void
  ) rethrows {
    let pid = event.pointee.pid
    if procs[pid] == nil {
      logger.warning("Process \(pid) not found!?")
      return
    }
    try body(&procs[pid]!)
  }

  func withEvent(
    _ eventHeader: UnsafeMutablePointer<mkcheck2_event_header>,
    _ body: (UnsafeMutablePointer<mkcheck2_event>) throws -> Void
  ) throws {
    try eventHeader.withMemoryRebound(to: mkcheck2_event.self, capacity: 1) {
      #if DEBUG
        let path = (try? $0.pathOrInode) ?? "bad string"
        logger.trace(
          "\(eventHeader.pointee.type) \(eventHeader.pointee.pid) \(eventHeader.pointee.uid) LINE=\(eventHeader.pointee.source_line) \(path)"
        )
      #endif
      try body($0)
    }
  }

  func withFatEvent(
    _ eventHeader: UnsafeMutablePointer<mkcheck2_event_header>,
    _ body: (UnsafeMutablePointer<mkcheck2_fat_event>) throws -> Void
  ) rethrows {
    try eventHeader.withMemoryRebound(to: mkcheck2_fat_event.self, capacity: 1) {
      #if DEBUG
        let path1 = (try? ($0.paths.0 ?? "")) ?? "bad string"
        let path2 = (try? ($0.paths.1 ?? "")) ?? "bad string"
        logger.trace(
          "\(eventHeader.pointee.type) \(eventHeader.pointee.pid) \(eventHeader.pointee.uid) LINE=\(eventHeader.pointee.source_line) \(path1) \(path2)"
        )
      #endif
      try body($0)
    }
  }

  func withFat2Event(
    _ eventHeader: UnsafeMutablePointer<mkcheck2_event_header>,
    _ body: (UnsafeMutablePointer<mkcheck2_fat2_event>) throws -> Void
  ) rethrows {
    try eventHeader.withMemoryRebound(to: mkcheck2_fat2_event.self, capacity: 1) {
      #if DEBUG
        let path1 = (try? ($0.paths.0 ?? "")) ?? "bad string"
        let path2 = (try? ($0.paths.1 ?? "")) ?? "bad string"
        logger.trace(
          "\(eventHeader.pointee.type) \(eventHeader.pointee.pid) \(eventHeader.pointee.uid) LINE=\(eventHeader.pointee.source_line) \(path1) \(path2)"
        )
      #endif
      try body($0)
    }
  }

  func handleEvent(_ eventHeader: UnsafeMutablePointer<mkcheck2_event_header>) throws {
    switch eventHeader.pointee.type {
    case .eventTypeExec:
      try withEvent(eventHeader) { event in
        let ppid = event.pointee.payload
        guard let parent = procs[ppid] else {
          logger.warning("Parent process \(ppid) not found!?")
          return
        }
        self.procs[eventHeader.pointee.pid] = try Process(
          pid: eventHeader.pointee.pid,
          parent: parent.uid,
          uid: eventHeader.pointee.uid,
          image: find(path: parent.normalize(path: event.path ?? "")),
          cwd: parent.cwd
        )
      }
    case .eventTypeExecAt:
      try withFatEvent(eventHeader) { event in
        let ppid = event.pointee.payload
        guard let parent = procs[ppid] else {
          logger.warning("Parent process \(ppid) not found!?")
          return
        }
        self.procs[eventHeader.pointee.pid] = try Process(
          pid: eventHeader.pointee.pid,
          parent: parent.uid,
          uid: eventHeader.pointee.uid,
          image: find(path: parent.normalize(base: event.paths.0 ?? "", path: event.paths.1 ?? "")),
          cwd: parent.cwd
        )
      }
    case .eventTypeExit:
      try withEvent(eventHeader) { event in
        if eventHeader.pointee.pid == root {
          rootExitCode = event.pointee.payload
        }
      }
    case .eventTypeClone:
      break
    // try withEvent(eventHeader) { event in
    //     let ppid = event.pointee.payload
    //     guard let parent = procs[ppid] else {
    //         // Check ppid in user land
    //         logger.warning("Parent process \(ppid) not found!?")
    //         return
    //     }
    //     self.procs[eventHeader.pointee.pid] = parent
    // }
    case .eventTypeChdir:
      try withEvent(eventHeader) { event in
        try withProcess(eventHeader) { process in
          try process.setCurrentWorkingDirectory(event.path!)
        }
      }
    case .eventTypeInput:
      try withEvent(eventHeader) { event in
        try withProcess(eventHeader) { try $0.addInput(event.pathOrInode, trace: self) }
      }
    case .eventTypeOutput:
      try withEvent(eventHeader) { event in
        try withProcess(eventHeader) { try $0.addOutput(event.pathOrInode, trace: self) }
      }
    case .eventTypeInputAt:
      try withFatEvent(eventHeader) { event in
        try withProcess(eventHeader) {
          let path = try $0.normalize(base: event.paths.0 ?? "", path: event.paths.1 ?? "")
          $0.addInput(path, trace: self)
        }
      }
    case .eventTypeOutputAt:
      try withFatEvent(eventHeader) { event in
        try withProcess(eventHeader) {
          let path = try $0.normalize(base: event.paths.0 ?? "", path: event.paths.1 ?? "")
          $0.addOutput(path, trace: self)
        }
      }
    case .eventTypeRemove:
      try withEvent(eventHeader) { event in
        try withProcess(eventHeader) { process in
          let path = try process.normalize(path: event.path!)
          unlink(path: path)
        }
      }
    case .eventTypeRemoveAt:
      try withFatEvent(eventHeader) { event in
        try withProcess(eventHeader) { process in
          let path = try process.normalize(base: event.paths.0 ?? "", path: event.paths.1 ?? "")
          unlink(path: path)
        }
      }
    case .eventTypeRename:
      try withFatEvent(eventHeader) { event in
        try withProcess(eventHeader) { process in
          guard case (let source?, let dest?) = try event.paths else { fatalError() }
          process.rename(
            source: process.normalize(path: source), dest: process.normalize(path: dest),
            trace: self)
        }
      }
    case .eventTypeRenameAt:
      try withFat2Event(eventHeader) { event in
        try withProcess(eventHeader) { process in
          guard
            case (let sourceBasePath?, let destBasePath?, let source?, let dest?) = try event.paths
          else { fatalError() }
          let sourceBase = process.normalize(path: sourceBasePath)
          let destBase = process.normalize(path: destBasePath)
          process.rename(
            source: process.normalize(base: sourceBase, path: source),
            dest: process.normalize(base: destBase, path: dest),
            trace: self
          )
        }
      }
    case .eventTypeLink:
      try withFatEvent(eventHeader) { event in
        try withProcess(eventHeader) { process in
          guard case (let source?, let dest?) = try event.paths else { fatalError() }
          process.link(
            target: process.normalize(path: source), linkPath: process.normalize(path: dest),
            trace: self)
        }
      }
    case .eventTypeLinkAt:
      try withFat2Event(eventHeader) { event in
        try withProcess(eventHeader) { process in
          guard
            case (let sourceBasePath?, let destBasePath?, let sourceLink?, let destLink?) =
              try event.paths
          else { fatalError() }
          let sourceBase = process.normalize(path: sourceBasePath)
          let destBase = process.normalize(path: destBasePath)
          process.link(
            target: process.normalize(base: sourceBase, path: sourceLink),
            linkPath: process.normalize(base: destBase, path: destLink),
            trace: self
          )
        }
      }
    case .eventTypeSymlink:
      try withFatEvent(eventHeader) { event in
        try withProcess(eventHeader) { process in
          guard case (let sourceLink?, let destRelative?) = try event.paths else { fatalError() }
          let parent = process.normalize(path: destRelative.removingLastComponent())
          let source = process.normalize(base: parent, path: sourceLink)
          let dest = process.normalize(path: destRelative)
          addDependency(source: source, dest: dest)
          process.addOutput(dest, trace: self)
        }
      }
    case .eventTypeSymlinkAt:
      try withFat2Event(eventHeader) { event in
        try withProcess(eventHeader) { process in
          guard case (let base?, let sourceLink?, let destRelative?, _) = try event.paths else {
            fatalError()
          }
          let parent = process.normalize(base: base, path: destRelative.removingLastComponent())
          let source = process.normalize(base: parent, path: sourceLink)
          let dest = process.normalize(base: base, path: destRelative)
          process.link(target: source, linkPath: dest, trace: self)
        }
      }
    }
  }
}
