# rbs_inline: enabled
module BuildFuzz
  class Tracer
    # @rbs command: Array[String]
    # @rbs sys: System
    # @rbs return: Array[String]
    def prefixed(command, sys)
      raise NotImplementedError
    end
  end

  class Mkcheck2Tracer < Tracer
    # @rbs @trace_path: String

    # @rbs trace_path: String
    def initialize(trace_path)
      @trace_path = trace_path
    end

    def prefixed(command, sys)
      FileUtils.mkdir_p(File.dirname(@trace_path))
      mkcheck2 = sys.which('mkcheck2')
      raise "mkcheck2 not found" unless mkcheck2
      [
        "sudo", "--preserve-env=REVISION,BUILD,SRC",
        mkcheck2, "-o", @trace_path, "--"
      ] + command
    end
  end

  class Mkcheck1Tracer < Tracer
    # @rbs @trace_path: String

    # @rbs trace_path: String
    def initialize(trace_path)
      @trace_path = trace_path
    end

    def prefixed(command, sys)
      FileUtils.mkdir_p(File.dirname(@trace_path))
      mkcheck = sys.which('mkcheck')
      raise "mkcheck not found" unless mkcheck
      [
        mkcheck, "--output=#{@trace_path}", "--"
      ] + command
    end
  end

  class StraceTracer < Tracer
    # @rbs @trace_path: String

    # @rbs trace_path: String
    def initialize(trace_path)
      @trace_path = trace_path
    end

    def prefixed(command, sys)
      FileUtils.mkdir_p(File.dirname(@trace_path))
      strace = sys.which('strace')
      raise "strace not found" unless strace
      [
        strace, "-o", @trace_path, "-f", "-tt", "-s", "10000", "--"
      ] + command
    end
  end

  class NoopTracer < Tracer
    def prefixed(command, sys)
      command
    end
  end
end
