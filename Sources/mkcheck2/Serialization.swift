import SystemPackage
import Foundation

enum Serialization {
    struct FileInfo: Codable {
        var id: FileID
        var name: FilePath
        var deleted: Bool?
        var exists: Bool?
        var deps: [FileID]?

        mutating func normalize() {
            deleted = deleted ?? false
            exists = exists ?? false
            deps = deps ?? []
        }

        var onelineAttributes: String {
            var attributes: [String] = []
            if deleted ?? false {
                attributes.append("deleted")
            }
            if exists ?? true {
                attributes.append("exists")
            }
            if let deps, !deps.isEmpty {
                attributes.append("deps=\(deps)")
            }
            return attributes.joined(separator: ", ")
        }
    }
    struct Process: Codable {
        let uid: UID
        let parent: UID
        var image: FileID
        var output: Set<FileID>?
        var input: Set<FileID>?
    }
}

/// Convert the given path to a relative path if it is under the given root directory
func relativePath(_ path: String, root: String) -> String {
    guard path.hasPrefix(root) else { return path }
    let relative = path.dropFirst(root.count)
    return relative.hasPrefix("/") ? String(relative.dropFirst()) : String(relative)
}

struct DumpFormat: Codable {
    var files: [Serialization.FileInfo]
    var procs: [Serialization.Process]

    mutating func normalize() {
        for i in files.indices {
            files[i].normalize()
        }
    }
}

extension Trace {
    func dump(output: inout some TextOutputStream) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        let format = DumpFormat(
            files: fileInfos.sorted { $0.key < $1.key }.map {
                Serialization.FileInfo(
                    id: $0.key,
                    name: $0.value.name,
                    deleted: $0.value.deleted,
                    exists: $0.value.exists,
                    deps: $0.value.deps
                )
            },
            procs: procs.values.uniqued().sorted { $0.uid < $1.uid }.map {
                Serialization.Process(
                    uid: $0.uid,
                    parent: $0.parent,
                    image: $0.image,
                    output: $0.outputs,
                    input: $0.inputs
                )
            }
        )
        let data = try! encoder.encode(format)
        output.write(String(data: data, encoding: .utf8)!)
    }

    func dumpDot(output: inout some TextOutputStream) {
        output.write("digraph trace {\n")
        for (pid, proc) in procs {
            let image = fileInfos[proc.image]?.name ?? "unknown"
            output.write("  PROCESS\(pid) [label=\"\(pid)\\n\(image)\"];\n")
            output.write("  FILE\(proc.image) -> PROCESS\(pid) [color=blue];\n")
            for inputFID in proc.inputs {
                output.write("  FILE\(inputFID) -> PROCESS\(pid) [color=blue];\n")
            }
            for outputFID in proc.outputs {
                output.write("  PROCESS\(pid) -> FILE\(outputFID) [color=red];\n")
            }
        }
        for (fid, info) in fileInfos {
            output.write("  FILE\(fid) [label=\"\(info.name)\"];\n")
        }
        output.write("}\n")
    }

    /// Dump the trace in ASCII art format
    func dumpAscii(output: inout some TextOutputStream) {
        TestSnapshotting.snapshot(self, output: &output)
    }

    struct TestSnapshotting {
        /// A snapshot of a process derived from a trace
        struct ProcessSnapshot: Comparable {
            var imageName: String
            var inputs: [String]
            var outputs: [String]

            func write(to outputStrem: inout some TextOutputStream) {
                outputStrem.write("PROCESS (image: \(imageName))\n")
                for input in inputs {
                    outputStrem.write("  INPUT \(input)\n")
                }
                for output in outputs {
                    outputStrem.write("  OUTPUT \(output)\n")
                }
            }

            static func < (lhs: ProcessSnapshot, rhs: ProcessSnapshot) -> Bool {
                if lhs.imageName != rhs.imageName { return lhs.imageName < rhs.imageName }
                if lhs.inputs != rhs.inputs {
                    for (l, r) in zip(lhs.inputs, rhs.inputs) {
                        if l != r { return l < r }
                    }
                    return lhs.inputs.count < rhs.inputs.count
                }
                if lhs.outputs != rhs.outputs {
                    for (l, r) in zip(lhs.outputs, rhs.outputs) {
                        if l != r { return l < r }
                    }
                    return lhs.outputs.count < rhs.outputs.count
                }
                return false
            }

            private static func shouldSnapshot(path: FilePath) -> Bool {
                // Ignore shared library files (.so, .so.2)
                // TODO: Remove this after we have a better way to snapshot only files under specific directories
                if path.extension == "so" { return false }
                if (try? #/\.so(:?\.\d+)*$/#.firstMatch(in: path.string)) != nil { return false }
                return true
            }

            private static func toFilePathList(_ fileIDs: Set<FileID>, trace: Trace, root: String) -> [String] {
                return fileIDs.filter {
                        trace.fileInfos[$0]?.deleted == false && shouldSnapshot(path: trace.fileInfos[$0]!.name)
                            && trace.fileInfos[$0]!.name.string.hasPrefix(root)
                    }
                    .map { relativePath(trace.fileInfos[$0]!.name.string, root: root) }
                    .sorted()
            }

            static func derive(trace: Trace, proc: Trace.Process, root: String) -> ProcessSnapshot? {
                guard trace.shouldTrace(pid: proc.pid) else { return nil }
                let imageName = relativePath(trace.fileInfos[proc.image]?.name.string ?? "unknown", root: root)
                return ProcessSnapshot(
                    imageName: imageName,
                    inputs: toFilePathList(proc.inputs, trace: trace, root: root),
                    outputs: toFilePathList(proc.outputs, trace: trace, root: root)
                )
            }
        }

        static func snapshot(_ trace: Trace, output: inout some TextOutputStream) {
            let cwd = FileManager.default.currentDirectoryPath
            let snapshots = trace.procs.values.uniqued().compactMap {
                ProcessSnapshot.derive(trace: trace, proc: $0, root: cwd)
            }.sorted()
            for snapshot in snapshots {
                snapshot.write(to: &output)
            }
        }
    }
}

fileprivate extension Sequence where Element: AnyObject {
    func uniqued() -> [Element] {
        var seen = Set<ObjectIdentifier>()
        return filter { seen.insert(ObjectIdentifier($0)).inserted }
    }
}
