# rbs_inline: enabled

module BuildFuzz
  class Git
    # @rbs @repo_path: String

    # @rbs @repo_path: String
    def initialize(repo_path)
      @repo_path = repo_path
    end

    # Return a list of revisions between the given two revisions
    # Note that the list is in reverse order, with the oldest revision
    # first and the newest last.
    # Also, the list excludes the start_rev and includes the end_rev.
    #
    # @rbs start_rev: String
    # @rbs end_rev: String
    # @rbs return: Array[String]
    def revisions_between(start_rev, end_rev)
      revs = IO.popen(["git", "-C", @repo_path, "rev-list", "#{start_rev}..#{end_rev}"], &:read)
      revs.lines.map(&:strip).reverse
    end
  end
end
