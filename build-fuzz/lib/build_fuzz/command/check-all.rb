# rbs_inline: enabled
module BuildFuzz
  class CheckAllCommand
    def self.run(args)
      sys_options = SystemOptions.new
      project_options = ProjectOptions.new
      # @type var options: { diag_file: String | nil }
      options = {
        diag_file: nil,
      }
      OptionParser.new do |opts|
        opts.banner = "Usage: #{$0} check-all <rev> [options]"

        sys_options.add_options(opts)
        project_options.add_options(opts)
        opts.on("--diag FILE", "Diagnostic output file") do |file|
          options[:diag_file] = file
        end
      end.parse!(args)

      rev = args.shift
      unless rev
        $stderr.puts "Missing <rev>"
        exit 1
      end

      sys = sys_options.sys
      project = project_options.project()
      diag_file = options[:diag_file]
      diags = DiagnosticEngine.new(diag_file ? File.open(diag_file, 'w') : $stderr, sys)
      graph_builder = GraphBuilder.new
      graph, plan = sys.span("Building graph") do
        graph_builder.build(project, sys, rev)
      end
      verifier = EveryEdgeVerifier.new(sys, project, graph)
      sys.span("Verifying all edges") do
        verifier.verify(plan)
      end
    end
  end
end
