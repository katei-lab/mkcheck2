# rbs_inline: enabled
module BuildFuzz
  class CheckCommand
    def self.run(args)
      sys_options = SystemOptions.new
      project_options = ProjectOptions.new
      # @type var options: { diag_file: String | nil }
      options = {
        diag_file: nil,
      }
      OptionParser.new do |opts|
        opts.banner = "Usage: #{$0} check <start-rev> <end-rev> [options]"

        sys_options.add_options(opts)
        project_options.add_options(opts)
        opts.on("--diag FILE", "Diagnostic output file") do |file|
          options[:diag_file] = file
        end
      end.parse!(args)

      start_rev, end_rev = args
      if !start_rev || !end_rev
        $stderr.puts "Missing <start-rev> or <end-rev>"
        exit 1
      end

      sys = sys_options.sys
      project = project_options.project()
      diag_file = options[:diag_file]
      diags = DiagnosticEngine.new(diag_file ? File.open(diag_file, 'w') : $stderr, sys)
      graph_builder = GraphBuilder.new
      verifier = HistoryVerifier.new(project, graph_builder, sys, diags)
      verifier.verify_between(start_rev, end_rev)
    end
  end
end
