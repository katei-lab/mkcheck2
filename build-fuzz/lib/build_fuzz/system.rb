# rbs_inline: enabled

module BuildFuzz
  # A context object that holds the state of the build system
  class System
    # @rbs @options: system_options

    # @rbs options: system_options
    def initialize(options)
      @options = options
      log_file = "/var/log/build-fuzz/system.log"
      FileUtils.mkdir_p(File.dirname(log_file))
      if options[:ddtrace]
        ENV['DD_ENV'] = 'production'
        ENV['DD_SERVICE'] = 'build-fuzz'
        ENV['DD_VERSION'] = '2.5.17'
        Datadog.configure do |c|
          c.tracing.log_injection = true
          c.tracing.instrument :semantic_logger, enabled: true
        end
        __skip__ = SemanticLogger.add_appender(
          file_name: log_file,
          formatter: SemanticLogger::Formatters::Json.new(log_host: false)
        )
      else
        __skip__ = SemanticLogger.add_appender(
          io: $stdout,
          formatter: SemanticLogger::Formatters::Color.new
        )
      end
      __skip__ = SemanticLogger.application="build-fuzz"
      __skip__ = SemanticLogger.default_level = :trace
    end

    # @rbs klass: untyped
    def logger(klass = "System")
      klass = if klass.is_a?(Class) || klass.is_a?(Module)
        klass.name
      elsif klass.is_a?(String)
        klass
      else
        klass.class.name
      end
      __skip__ = SemanticLogger::Logger.new(klass)
    end

    # @rbs name: String
    # @rbs kwargs: Hash[Symbol, String]
    # @rbs b: ^{ -> void }
    def span(name, **kwargs, &block)
      return block&.call() unless @options[:ddtrace]
      Datadog::Tracing.trace(name, service: 'build-fuzz', resource: name, tags: kwargs, &block)
    end

    # @rbs command: Array[String]
    # @rbs env: Hash[String, String]
    def log_command(command, env)
      if @options[:verbose]
        command_text = command.map(&:shellescape).join(' ')
        if env.size > 0
          command_text = env.map { |k, v| "#{k}=#{v.shellescape}" }.join(' ') + ' ' + command_text
        end
        logger.debug command_text
      end
    end

    # @rbs command: Array[String]
    # @rbs env: Hash[String, String]
    def run_command(command, env = {})
      log_command(command, env)
      # FIXME: https://github.com/ruby/rbs/pull/2075
      __skip__ = Kernel.system(env, *command, exception: true)
    end

    # Run a command silently
    # If the command fails, it raises an exception and logs the stdout and stderr
    def run_command_silent(command, env = {})
      log_command(command, env)
      stdout, stderr, status = Open3.capture3(env, *command)
      unless status.success?
        logger.error "Command failed: #{command.join(' ')}"
        logger.error "stdout: #{stdout}"
        logger.error "stderr: #{stderr}"
        raise "Command failed: #{command.join(' ')}"
      end
    end

    # Run a command and log it
    #
    # @rbs command: Array[String]
    # @rbs env: Hash[String, String]
    # @rbs return: run_command_with_logging_return
    def run_command_with_logging(command, env = {})
      log_command(command, env)

      if $stdout.tty?
        printer = StatusPrinter.new
      else
        printer = nil
      end
      begin
        _, stdout, stderr, wait_thr = if env
          Open3.popen3(env, *command)
        else
          Open3.popen3(*command)
        end
        out_ino = stdout.stat.ino
        err_ino = stderr.stat.ino
        mux = Mutex.new
        out = String.new
        err = String.new
        readers =
          [
            [stdout, :stdout, out],
            [stderr, :stderr, err]
          ].map do |io, name, str|
            reader =
              Thread.new do
                while (line = io.gets)
                  mux.synchronize do
                    printer.print(line) if printer
                    str << line
                  end
                end
              end
            reader.report_on_exception = false
            reader
          end
        readers.each(&:join)

        status = wait_thr.value
        unless status.success?
          logger(self).error("Command failed", command: command, status: status.exitstatus, stdout: out, stderr: err)
          raise "Command failed: #{command.join(' ')} (status: #{status.exitstatus})"
        end

        return { stdout: out, stderr: err, stdout_ino: out_ino, stderr_ino: err_ino }
      ensure
        printer.done if printer
      end
    end

    # Human readable status printer for the build.
    class StatusPrinter
      def initialize
        @mutex = Mutex.new
        @counter = 0
        @indicators = "|/-\\"
      end

      def print(message)
        require "io/console"
        @mutex.synchronize do
          $stdout.print "\e[K"
          first_line = message.lines(chomp: true).first || ""

          # Make sure we don't line-wrap the output
          size =
            __skip__ =
              IO.respond_to?(:console_size) ? IO.console_size : IO.console.winsize
          terminal_width = size[1].to_i.nonzero? || 80
          width_limit = terminal_width / 2 - 3

          if first_line.length > width_limit
            first_line = (first_line[0..width_limit - 5] || "") + "..."
          end
          indicator = @indicators[@counter] || " "
          to_print = "  " + indicator + " " + first_line
          $stdout.print to_print
          $stdout.print "\e[1A\n"
          @counter += 1
          @counter = 0 if @counter >= @indicators.length
        end
      end

      def done
        @mutex.synchronize { $stdout.print "\e[K" }
      end
    end

    # Execute a command and return the stdout
    # @rbs command: Array[String]
    # @rbs env: Hash[String, String]
    # @rbs return: String
    def run_command_output(command, env = {})
      IO.popen(env, command, &:read)
    end

    def bare_repo_path(name)
      File.join(@options[:cache_dir] || @options[:build_dir], "repositories", name)
    end

    def checkout_path(name, revision)
      File.join(@options[:build_dir], "checkouts", name)
    end

    def project_build_dir(name, revision)
      File.join(@options[:build_dir], "builds", name)
    end

    def artifact_path(project_name, revision)
      File.join(self.output_dir, project_name, "#{revision}.json")
    end

    def log_dir_path(project_name, revision)
      File.join(self.output_dir, project_name, revision)
    end

    def output_dir
      @options[:output_dir] || File.join(@options[:build_dir], 'output')
    end

    def which(command)
      env_exe = ENV["#{command.upcase}_EXE"]
      return env_exe if env_exe

      paths = ENV['PATH']
      return nil unless paths
      paths.split(File::PATH_SEPARATOR).each do |path|
        exe = File.join(path, command)
        return exe if File.executable?(exe)
      end
      nil
    end
  end
end
