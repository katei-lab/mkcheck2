# rbs_inline: enabled

require 'logger'

module BuildFuzz
  class DownloadCommand
    # @rbs args: Array[String]
    def self.run(args)
      # @type var options: { build_fuzz_rev: String | nil }
      options = {}
      sys_options = SystemOptions.new

      OptionParser.new do |opts|
        opts.banner = "Usage: #{$0} download [options]"

        opts.on("--build-fuzz-rev REV", "Git revision of build-fuzz") do |rev|
          options[:build_fuzz_rev] = rev
        end

        sys_options.add_options(opts)
      end.parse!(args)

      build_fuzz_rev = options[:build_fuzz_rev]
      if !build_fuzz_rev
        $stderr.puts "--build-fuzz-rev <rev> is required"
        exit 1
      end

      sys = sys_options.sys
      github_token = ENV['GITHUB_TOKEN'] or raise "Missing GITHUB_TOKEN environment variable"
      github = GitHub.new(github_token, "kateinoigakukun/build-fuzz")
      collector = Collector.new(sys, github)
      logger = Logger.new($stderr)

      collector.download(build_fuzz_rev, logger)
    end    
  end
end
