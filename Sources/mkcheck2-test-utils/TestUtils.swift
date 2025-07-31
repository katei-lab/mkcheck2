import ArgumentParser
import Glibc
import SystemPackage
import mkcheck2syslinux

@main
struct TestUtils: ParsableCommand {
  static let configuration = CommandConfiguration(
    abstract: "Utilities for testing mkcheck2",
    discussion: """
      This tool provides utilities for testing mkcheck2.
      The main purpose of this tool instead of using traditional shell scripting tools
      is to ensure expected system calls are dispatched correctly.

      For example, recent coreutils "mv" command uses renameat(2) system call
      instead of rename(2) system call, so we can't use it to test rename(2) system call.

      This tool provides a simple way to test system calls by directly calling them.
      """,
    subcommands: [
      Write.self, Rename.self, RenameAt.self, RemoveDir.self, Readlink.self, ReadlinkAt.self,
      Utime.self, MkdirAt.self, UnlinkAt.self, FaccessAt.self, LinkAt.self, SymlinkAt.self,
      ForkExecveAt.self,
    ]
  )

  struct Write: ParsableCommand {
    @Option(help: "Options for opening the file.")
    var options: [FileDescriptor.OpenOptions] = []

    @Argument(help: "The file to write to.")
    var file: String

    @Argument(help: "The text to write.")
    var text: String

    func run() throws {
      let path = FilePath(file)
      let options = FileDescriptor.OpenOptions(options)
      let fd = try FileDescriptor.open(
        path, .writeOnly, options: options, permissions: .ownerReadWriteExecute)
      _ = try fd.closeAfter { try fd.writeAll(text.utf8) }
    }
  }

  struct Rename: ParsableCommand {
    @Argument(help: "The old file name.")
    var old: String

    @Argument(help: "The new file name.")
    var new: String

    func run() throws {
      let oldPath = FilePath(old)
      let newPath = FilePath(new)
      try oldPath.withPlatformString { oldPath in
        try newPath.withPlatformString { newPath in
          if rename(oldPath, newPath) != 0 {
            throw Errno()
          }
        }
      }
    }
  }

  struct RenameAt: ParsableCommand {
    @Argument(help: "The directory to rename the file.")
    var dir1: String

    @Argument(help: "The old file name.")
    var old: String

    @Argument(help: "The directory to rename to.")
    var dir2: String

    @Argument(help: "The new file name.")
    var new: String

    func run() throws {
      let dir1Path = FilePath(dir1)
      let dir2Path = FilePath(dir2)
      let oldPath = FilePath(old)
      let newPath = FilePath(new)
      try dir1Path.withPlatformString { dir1Path in
        try dir2Path.withPlatformString { dir2Path in
          try oldPath.withPlatformString { oldPath in
            try newPath.withPlatformString { newPath in
              let dir1Fd = try FileDescriptor.open(dir1Path, .readOnly)
              let dir2Fd = try FileDescriptor.open(dir2Path, .readOnly)
              let result = renameat(dir1Fd.rawValue, oldPath, dir2Fd.rawValue, newPath)
              if result != 0 {
                throw Errno()
              }
            }
          }
        }
      }
    }
  }

  struct RemoveDir: ParsableCommand {
    @Argument(help: "The directory to remove.")
    var dir: String

    func run() throws {
      let path = FilePath(dir)
      try path.withPlatformString { path in
        if rmdir(path) != 0 {
          throw Errno()
        }
      }
    }
  }

  struct Readlink: ParsableCommand {
    @Argument(help: "The symbolic link to read.")
    var link: String

    func run() throws {
      let path = FilePath(link)
      try path.withPlatformString { path in
        let buffer = UnsafeMutablePointer<CChar>.allocate(capacity: Int(PATH_MAX))
        defer { buffer.deallocate() }
        let length = readlink(path, buffer, Int(PATH_MAX))
        if length == -1 {
          throw Errno()
        }
        let link = String(cString: buffer)
        print(link)
      }
    }
  }

  struct ReadlinkAt: ParsableCommand {
    @Argument(help: "The directory to resolve the symbolic link.")
    var dir: String

    @Argument(help: "The symbolic link to read.")
    var link: String

    func run() throws {
      let dirPath = FilePath(dir)
      let linkPath = FilePath(link)
      try dirPath.withPlatformString { dirPath in
        try linkPath.withPlatformString { linkPath in
          let dirFd = try FileDescriptor.open(dirPath, .readOnly)
          let buffer = UnsafeMutablePointer<CChar>.allocate(capacity: Int(PATH_MAX))
          defer { buffer.deallocate() }
          let length = readlinkat(dirFd.rawValue, linkPath, buffer, Int(PATH_MAX))
          if length == -1 {
            throw Errno()
          }
          let link = String(cString: buffer)
          print(link)
        }
      }
    }
  }

  struct Utime: ParsableCommand {
    @Argument(help: "The file to update the access and modification times.")
    var file: String

    func run() throws {
      let path = FilePath(file)
      let now = time(nil)
      var times = utimbuf(actime: now, modtime: now)
      try path.withPlatformString { path in
        let result = utime(path, &times)
        if result != 0 {
          throw Errno()
        }
      }
    }
  }

  struct MkdirAt: ParsableCommand {
    @Argument(help: "The directory to create the new directory.")
    var dir: String

    @Argument(help: "The new directory to create.")
    var newDir: String

    func run() throws {
      let dirPath = FilePath(dir)
      let newDirPath = FilePath(newDir)
      try dirPath.withPlatformString { dirPath in
        try newDirPath.withPlatformString { newDirPath in
          let dirFd = try FileDescriptor.open(dirPath, .readOnly)
          let result = mkdirat(dirFd.rawValue, newDirPath, S_IRWXU)
          if result != 0 {
            throw Errno()
          }
        }
      }
    }
  }

  struct UnlinkAt: ParsableCommand {
    @Argument(help: "The directory to remove the file.")
    var dir: String

    @Argument(help: "The file to remove.")
    var file: String

    func run() throws {
      let dirPath = FilePath(dir)
      let filePath = FilePath(file)
      try dirPath.withPlatformString { dirPath in
        try filePath.withPlatformString { filePath in
          let dirFd = try FileDescriptor.open(dirPath, .readOnly)
          let result = unlinkat(dirFd.rawValue, filePath, 0)
          if result != 0 {
            throw Errno()
          }
        }
      }
    }
  }

  struct FaccessAt: ParsableCommand {
    @Argument(help: "The directory to access the file.")
    var dir: String

    @Argument(help: "The file to access.")
    var file: String

    func run() throws {
      let dirPath = FilePath(dir)
      let filePath = FilePath(file)
      try dirPath.withPlatformString { dirPath in
        try filePath.withPlatformString { filePath in
          let dirFd = try FileDescriptor.open(dirPath, .readOnly)
          let result = faccessat(dirFd.rawValue, filePath, R_OK, 0)
          if result != 0 {
            throw Errno()
          }
        }
      }
    }
  }

  struct LinkAt: ParsableCommand {
    @Argument(help: "The directory to create the link.")
    var dir1: String

    @Argument(help: "The file to link.")
    var file: String

    @Argument(help: "The directory to link to.")
    var dir2: String

    @Argument(help: "The new link name.")
    var link: String

    func run() throws {
      let dir1Path = FilePath(dir1)
      let dir2Path = FilePath(dir2)
      let filePath = FilePath(file)
      let linkPath = FilePath(link)
      try dir1Path.withPlatformString { dir1Path in
        try dir2Path.withPlatformString { dir2Path in
          try filePath.withPlatformString { filePath in
            try linkPath.withPlatformString { linkPath in
              let dir1Fd = try FileDescriptor.open(dir1Path, .readOnly)
              let dir2Fd = try FileDescriptor.open(dir2Path, .readOnly)
              let result = linkat(dir1Fd.rawValue, filePath, dir2Fd.rawValue, linkPath, 0)
              if result != 0 {
                throw Errno()
              }
            }
          }
        }
      }
    }
  }

  struct SymlinkAt: ParsableCommand {
    @Argument(help: "The directory to create the symbolic link.")
    var dir: String

    @Argument(help: "The target of the symbolic link.")
    var target: String

    @Argument(help: "The new symbolic link name.")
    var link: String

    func run() throws {
      let dirPath = FilePath(dir)
      let targetPath = FilePath(target)
      let linkPath = FilePath(link)
      try dirPath.withPlatformString { dirPath in
        try targetPath.withPlatformString { targetPath in
          try linkPath.withPlatformString { linkPath in
            let dirFd = try FileDescriptor.open(dirPath, .readOnly)
            let result = symlinkat(targetPath, dirFd.rawValue, linkPath)
            if result != 0 {
              throw Errno()
            }
          }
        }
      }
    }
  }

  struct ForkExecveAt: ParsableCommand {
    @Argument(help: "The base directory to execute the program.")
    var dir: String

    @Argument(help: "The program to execute.")
    var program: String

    @Argument(help: "The arguments to pass to the program.")
    var arguments: [String] = []

    func run() throws {
      let dirPath = FilePath(dir)
      let programPath = FilePath(program)
      let dfd = try FileDescriptor.open(dirPath, .readOnly)
      defer { _ = try? dfd.close() }
      try programPath.withCString { programPath in
        let programPath = strdup(programPath)!
        let argv: [UnsafeMutablePointer<CChar>?] =
          [programPath] + arguments.map { strdup($0) } + [nil]
        let envp = [strdup("PATH=/bin:/usr/bin"), nil]

        let pid = fork()

        switch pid {
        case -1:
          throw Errno()
        case 0:
          // Child process
          let result = execveat(dfd.rawValue, programPath, argv, envp, 0)
          if result != 0 {
            throw Errno()
          }
        case let pid:
          // Parent process
          var status: Int32 = 0
          let result = waitpid(pid, &status, 0)
          if result == -1 {
            throw Errno()
          }
          if swift_WIFEXITED(status) != 0 {
            let exitStatus = swift_WEXITSTATUS(status)
            if exitStatus != 0 {
              throw Errno(code: Int32(exitStatus))
            }
          } else {
            throw Errno()
          }
        }
      }
    }
  }
}

struct Errno: Error, CustomDebugStringConvertible {
  let code: Int32

  var debugDescription: String {
    String(cString: strerror(code))
  }

  init(code: Int32 = errno) {
    self.code = code
  }
}

extension FileDescriptor.OpenOptions: @retroactive ExpressibleByArgument {
  public init?(argument: String) {
    switch argument {
    case "create": self = .create
    case "truncate": self = .truncate
    case "append": self = .append
    default: return nil
    }
  }
}
