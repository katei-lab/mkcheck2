module BuildFuzz
  Trace = Struct.new(:procs, :files)
  Process = Struct.new(:uid, :image, :input, :output, :parent)

  class << Trace
    def parse(path)
      data = JSON.parse(File.read(path))
      files = {}
      data['files'].each { |file| files[file['id']] = file }
      procs = {}
      data['procs'].each do |proc|
        proc = Process.new(proc['uid'], proc['image'], proc['input'], proc['output'], proc['parent'])
        procs[proc['uid']] = proc
        proc.image = files[proc.image]['name']
        proc.input = proc.input&.map { |uid| files[uid]['name'] }
        proc.output = proc.output&.map { |uid| files[uid]['name'] }
      end

      # Link parents
      procs.each do |uid, proc|
        parent = procs[proc['parent']]
        proc['parent'] = parent if parent
      end

      Trace.new(procs, files)
    end
  end

  class Trace
    def normalize_paths
      # FIXME: Replace 
    end
  end
end
